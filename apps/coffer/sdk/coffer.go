// Package coffer is a Coffer client in one file, using only the Go standard library (Go 1.24+).
// Secrets are encrypted and decrypted here; the Coffer server only ever sees ciphertext.
//
//	COFFER_URL=__COFFER_URL__        (optional; defaults to the URL below)
//	COFFER_CLIENT_ID=cfi_...
//	COFFER_CLIENT_SECRET=cfs_...
//
//	c, err := coffer.FromEnv()
//	all, err := c.ListAllSecrets(ctx)                 // map[string]string
//	db, ok, err := c.GetSecret(ctx, "DATABASE_URL")
//	version, err := c.WriteSecret(ctx, "API_TOKEN", "s3cr3t") // needs a read-write client ID
//	deleted, err := c.DeleteSecret(ctx, "API_TOKEN")
//
// Protocol (Coffer v1). HKDF is HKDF-SHA256 with a 32-byte zero salt and 32-byte output.
//
//	authKey  = HKDF(clientSecret, "coffer/v1/machine-auth")   sent as "Bearer <clientId>.<base64 authKey>"
//	wrapKey  = HKDF(clientSecret, "coffer/v1/machine-wrap")
//	envKey   = AES-256-GCM-open(wrapKey, identity.wrappedKey, aad "coffer/v1/machine-key/<clientId>")
//	encKey   = HKDF(envKey, "coffer/v1/secret-enc");  indexKey = HKDF(envKey, "coffer/v1/secret-index")
//	mac      = hex(HMAC-SHA256(indexKey, name))
//	secret   = AES-256-GCM(encKey, JSON {"name","value"}, aad "coffer/v1/secret/<envId>/<mac>")
//	{iv, ct} are base64; ct is ciphertext followed by the 16-byte tag.
package coffer

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultURL = "__COFFER_URL__"

var clientIDPattern = regexp.MustCompile(`^cfi_[A-Za-z0-9_-]{22}$`)

// Error is returned for non-2xx API responses.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("coffer: %s (%d)", e.Message, e.Status) }

// Identity describes what a client ID can access.
type Identity struct {
	ClientID    string `json:"clientId"`
	Scope       string `json:"scope"`
	ProjectID   string `json:"projectId"`
	Project     string `json:"project"`
	EnvID       string `json:"envId"`
	Environment string `json:"environment"`
	WrappedKey  sealed `json:"wrappedKey"`
}

type sealed struct {
	IV string `json:"iv"`
	CT string `json:"ct"`
}

type secretRow struct {
	Mac     string `json:"mac"`
	IV      string `json:"iv"`
	CT      string `json:"ct"`
	Version int    `json:"version"`
}

type plaintext struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type keys struct {
	identity Identity
	enc      cipher.AEAD
	index    []byte
}

// Client talks to one Coffer environment. Safe for concurrent use.
type Client struct {
	HTTP         *http.Client
	url          string
	clientID     string
	clientSecret string
	auth         string
	mu           sync.Mutex
	keys         *keys
}

// New creates a client. url is the Coffer base URL, e.g. https://coffer.example.com.
func New(url, clientID, clientSecret string) (*Client, error) {
	if !clientIDPattern.MatchString(clientID) {
		return nil, errors.New("coffer: invalid client ID")
	}
	if !strings.HasPrefix(clientSecret, "cfs_") {
		return nil, errors.New("coffer: invalid client secret")
	}
	authKey := derive([]byte(clientSecret), "coffer/v1/machine-auth")
	return &Client{
		HTTP:         &http.Client{Timeout: 30 * time.Second},
		url:          strings.TrimRight(url, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		auth:         "Bearer " + clientID + "." + base64.StdEncoding.EncodeToString(authKey),
	}, nil
}

// FromEnv reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET and optionally COFFER_URL.
func FromEnv() (*Client, error) {
	id, secret := os.Getenv("COFFER_CLIENT_ID"), os.Getenv("COFFER_CLIENT_SECRET")
	if id == "" || secret == "" {
		return nil, errors.New("coffer: set COFFER_CLIENT_ID and COFFER_CLIENT_SECRET")
	}
	url := os.Getenv("COFFER_URL")
	if url == "" {
		url = defaultURL
	}
	return New(url, id, secret)
}

// ListAllSecrets returns every secret of this client's environment, by name.
func (c *Client) ListAllSecrets(ctx context.Context) (map[string]string, error) {
	k, err := c.load(ctx)
	if err != nil {
		return nil, err
	}
	var res struct {
		Secrets []secretRow `json:"secrets"`
	}
	if err := c.do(ctx, http.MethodGet, "/secrets", nil, &res); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(res.Secrets))
	for _, row := range res.Secrets {
		p, err := c.decrypt(k, row)
		if err != nil {
			return nil, err
		}
		out[p.Name] = p.Value
	}
	return out, nil
}

// GetSecret returns a secret's value; ok is false if it does not exist.
func (c *Client) GetSecret(ctx context.Context, name string) (value string, ok bool, err error) {
	k, err := c.load(ctx)
	if err != nil {
		return "", false, err
	}
	var row secretRow
	if err := c.do(ctx, http.MethodGet, "/secrets/"+mac(k, name), nil, &row); err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusNotFound {
			return "", false, nil
		}
		return "", false, err
	}
	p, err := c.decrypt(k, row)
	if err != nil {
		return "", false, err
	}
	return p.Value, true, nil
}

// WriteSecret creates or replaces a secret and returns its new version number.
func (c *Client) WriteSecret(ctx context.Context, name, value string) (int, error) {
	if name == "" {
		return 0, errors.New("coffer: empty secret name")
	}
	k, err := c.load(ctx)
	if err != nil {
		return 0, err
	}
	m := mac(k, name)
	pt, err := json.Marshal(plaintext{Name: name, Value: value})
	if err != nil {
		return 0, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return 0, err
	}
	ct := k.enc.Seal(nil, iv, pt, []byte("coffer/v1/secret/"+k.identity.EnvID+"/"+m))
	var row secretRow
	body := sealed{IV: base64.StdEncoding.EncodeToString(iv), CT: base64.StdEncoding.EncodeToString(ct)}
	if err := c.do(ctx, http.MethodPut, "/secrets/"+m, body, &row); err != nil {
		return 0, err
	}
	return row.Version, nil
}

// DeleteSecret deletes a secret; it returns false if the secret did not exist.
func (c *Client) DeleteSecret(ctx context.Context, name string) (bool, error) {
	k, err := c.load(ctx)
	if err != nil {
		return false, err
	}
	var res struct {
		Deleted bool `json:"deleted"`
	}
	if err := c.do(ctx, http.MethodDelete, "/secrets/"+mac(k, name), nil, &res); err != nil {
		return false, err
	}
	return res.Deleted, nil
}

// Identity returns the project, environment and scope of this client ID.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	k, err := c.load(ctx)
	if err != nil {
		return Identity{}, err
	}
	id := k.identity
	id.WrappedKey = sealed{}
	return id, nil
}

func derive(ikm []byte, info string) []byte {
	key, err := hkdf.Key(sha256.New, ikm, make([]byte, 32), info, 32)
	if err != nil {
		panic(err) // only for invalid lengths
	}
	return key
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func open(aead cipher.AEAD, s sealed, aad string) ([]byte, error) {
	iv, err := base64.StdEncoding.DecodeString(s.IV)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(s.CT)
	if err != nil {
		return nil, err
	}
	if len(iv) != aead.NonceSize() {
		return nil, errors.New("coffer: bad nonce")
	}
	return aead.Open(nil, iv, ct, []byte(aad))
}

func mac(k *keys, name string) string {
	h := hmac.New(sha256.New, k.index)
	h.Write([]byte(name))
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Client) decrypt(k *keys, row secretRow) (plaintext, error) {
	var p plaintext
	pt, err := open(k.enc, sealed{IV: row.IV, CT: row.CT}, "coffer/v1/secret/"+k.identity.EnvID+"/"+row.Mac)
	if err != nil {
		return p, fmt.Errorf("coffer: cannot decrypt secret: %w", err)
	}
	if err := json.Unmarshal(pt, &p); err != nil {
		return p, err
	}
	if mac(k, p.Name) != row.Mac {
		return p, errors.New("coffer: secret name does not match its index")
	}
	return p, nil
}

func (c *Client) load(ctx context.Context) (*keys, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys != nil {
		return c.keys, nil
	}
	var id Identity
	if err := c.do(ctx, http.MethodGet, "/identity", nil, &id); err != nil {
		return nil, err
	}
	wrap, err := newGCM(derive([]byte(c.clientSecret), "coffer/v1/machine-wrap"))
	if err != nil {
		return nil, err
	}
	envKey, err := open(wrap, id.WrappedKey, "coffer/v1/machine-key/"+c.clientID)
	if err != nil {
		return nil, fmt.Errorf("coffer: cannot unwrap environment key (wrong client secret?): %w", err)
	}
	enc, err := newGCM(derive(envKey, "coffer/v1/secret-enc"))
	if err != nil {
		return nil, err
	}
	c.keys = &keys{identity: id, enc: enc, index: derive(envKey, "coffer/v1/secret-index")}
	clear(envKey)
	return c.keys, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+"/api/v1"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = e.Error
		}
		if e.Message == "" {
			e.Message = res.Status
		}
		return &Error{Status: res.StatusCode, Code: e.Error, Message: e.Message}
	}
	return json.Unmarshal(data, out)
}
