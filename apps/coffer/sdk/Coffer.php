<?php
// Coffer client in one file. PHP 8.1+ with the openssl, curl and json extensions; no Composer packages.
// Secrets are encrypted and decrypted here; the Coffer server only ever sees ciphertext.
//
//   COFFER_URL=__COFFER_URL__        (optional; defaults to the URL below)
//   COFFER_CLIENT_ID=cfi_...
//   COFFER_CLIENT_SECRET=cfs_...
//
//   require_once 'Coffer.php';
//   $coffer = Coffer::fromEnv();
//   $all = $coffer->listAllSecrets();               // ['DATABASE_URL' => '...', ...]
//   $db = $coffer->getSecret('DATABASE_URL');       // null if missing
//   $coffer->writeSecret('API_TOKEN', 's3cr3t');    // needs a read-write client ID
//   $coffer->deleteSecret('API_TOKEN');
//
// Protocol (Coffer v1). HKDF is HKDF-SHA256 with a 32-byte zero salt and 32-byte output.
//   authKey  = HKDF(clientSecret, "coffer/v1/machine-auth")   sent as "Bearer <clientId>.<base64 authKey>"
//   wrapKey  = HKDF(clientSecret, "coffer/v1/machine-wrap")
//   envKey   = AES-256-GCM-open(wrapKey, identity.wrappedKey, aad "coffer/v1/machine-key/<clientId>")
//   encKey   = HKDF(envKey, "coffer/v1/secret-enc");  indexKey = HKDF(envKey, "coffer/v1/secret-index")
//   mac      = hex(HMAC-SHA256(indexKey, name))
//   secret   = AES-256-GCM(encKey, JSON {"name","value"}, aad "coffer/v1/secret/<envId>/<mac>")
//   {iv, ct} are base64; ct is ciphertext followed by the 16-byte tag.

declare(strict_types=1);

final class CofferException extends RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode, string $message)
    {
        parent::__construct("Coffer: {$message} ({$status})", $status);
    }
}

final class Coffer
{
    private const DEFAULT_URL = '__COFFER_URL__';
    private const TAG = 16;

    private string $url;
    private string $auth;
    private ?array $identity = null;
    private string $encKey = '';
    private string $indexKey = '';

    public function __construct(string $url, private string $clientId, private string $clientSecret, private int $timeout = 30)
    {
        if (!preg_match('/^cfi_[A-Za-z0-9_-]{22}$/', $clientId)) {
            throw new InvalidArgumentException('Coffer: invalid client ID');
        }
        if (!str_starts_with($clientSecret, 'cfs_')) {
            throw new InvalidArgumentException('Coffer: invalid client secret');
        }
        $this->url = rtrim($url, '/');
        $this->auth = 'Bearer ' . $clientId . '.' . base64_encode(self::derive($clientSecret, 'coffer/v1/machine-auth'));
    }

    /** Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET and optionally COFFER_URL (getenv, $_ENV or $_SERVER). */
    public static function fromEnv(): self
    {
        $id = self::env('COFFER_CLIENT_ID');
        $secret = self::env('COFFER_CLIENT_SECRET');
        if ($id === null || $secret === null) {
            throw new RuntimeException('Coffer: set COFFER_CLIENT_ID and COFFER_CLIENT_SECRET');
        }
        return new self(self::env('COFFER_URL') ?? self::DEFAULT_URL, $id, $secret);
    }

    /** @return array<string, string> All secrets of this client's environment, by name. */
    public function listAllSecrets(): array
    {
        $this->load();
        $out = [];
        foreach ($this->request('GET', '/secrets')['secrets'] as $row) {
            [$name, $value] = $this->decrypt($row);
            $out[$name] = $value;
        }
        return $out;
    }

    /** One secret's value, or null if it does not exist. */
    public function getSecret(string $name): ?string
    {
        $this->load();
        try {
            return $this->decrypt($this->request('GET', '/secrets/' . $this->mac($name)))[1];
        } catch (CofferException $e) {
            if ($e->status === 404) {
                return null;
            }
            throw $e;
        }
    }

    /** Create or replace a secret. Returns its new version number. */
    public function writeSecret(string $name, string $value): int
    {
        if ($name === '') {
            throw new InvalidArgumentException('Coffer: empty secret name');
        }
        $this->load();
        $mac = $this->mac($name);
        $plain = json_encode(['name' => $name, 'value' => $value], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $sealed = self::seal($this->encKey, $plain, "coffer/v1/secret/{$this->identity['envId']}/{$mac}");
        return (int) $this->request('PUT', '/secrets/' . $mac, $sealed)['version'];
    }

    /** Returns false if the secret did not exist. */
    public function deleteSecret(string $name): bool
    {
        $this->load();
        return (bool) $this->request('DELETE', '/secrets/' . $this->mac($name))['deleted'];
    }

    /** @return array{clientId: string, scope: string, projectId: string, project: string, envId: string, environment: string} */
    public function identity(): array
    {
        $this->load();
        $id = $this->identity;
        unset($id['wrappedKey']);
        return $id;
    }

    private static function env(string $key): ?string
    {
        $v = getenv($key);
        if ($v === false || $v === '') {
            $v = $_ENV[$key] ?? $_SERVER[$key] ?? null;
        }
        return is_string($v) && $v !== '' ? $v : null;
    }

    private static function derive(string $ikm, string $info): string
    {
        return hash_hkdf('sha256', $ikm, 32, $info, str_repeat("\0", 32));
    }

    private function mac(string $name): string
    {
        return hash_hmac('sha256', $name, $this->indexKey);
    }

    private static function open(string $key, array $sealed, string $aad): string
    {
        $iv = base64_decode($sealed['iv'], true);
        $data = base64_decode($sealed['ct'], true);
        if ($iv === false || $data === false || strlen($data) < self::TAG) {
            throw new RuntimeException('Coffer: malformed ciphertext');
        }
        $plain = openssl_decrypt(substr($data, 0, -self::TAG), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, substr($data, -self::TAG), $aad);
        if ($plain === false) {
            throw new RuntimeException('Coffer: decryption failed (wrong key or tampered data)');
        }
        return $plain;
    }

    private static function seal(string $key, string $plain, string $aad): array
    {
        $iv = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, self::TAG);
        if ($ct === false) {
            throw new RuntimeException('Coffer: encryption failed');
        }
        return ['iv' => base64_encode($iv), 'ct' => base64_encode($ct . $tag)];
    }

    /** @return array{0: string, 1: string} */
    private function decrypt(array $row): array
    {
        $p = json_decode(self::open($this->encKey, $row, "coffer/v1/secret/{$this->identity['envId']}/{$row['mac']}"), true, 4, JSON_THROW_ON_ERROR);
        if (!hash_equals($row['mac'], $this->mac($p['name']))) {
            throw new RuntimeException('Coffer: secret name does not match its index');
        }
        return [$p['name'], $p['value']];
    }

    private function load(): void
    {
        if ($this->identity !== null) {
            return;
        }
        $id = $this->request('GET', '/identity');
        $wrap = self::derive($this->clientSecret, 'coffer/v1/machine-wrap');
        $envKey = self::open($wrap, $id['wrappedKey'], "coffer/v1/machine-key/{$this->clientId}");
        $this->encKey = self::derive($envKey, 'coffer/v1/secret-enc');
        $this->indexKey = self::derive($envKey, 'coffer/v1/secret-index');
        $this->identity = $id;
    }

    private function request(string $method, string $path, ?array $body = null): array
    {
        $headers = ['Authorization: ' . $this->auth, 'Accept: application/json'];
        $ch = curl_init($this->url . '/api/v1' . $path);
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        ];
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = json_encode($body, JSON_THROW_ON_ERROR);
            $headers[] = 'Content-Type: application/json';
        }
        $opts[CURLOPT_HTTPHEADER] = $headers;
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        if ($raw === false) {
            throw new CofferException(0, 'network_error', curl_error($ch));
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $data = json_decode((string) $raw, true);
        if ($status < 200 || $status > 299) {
            $code = is_array($data) ? (string) ($data['error'] ?? 'http_error') : 'http_error';
            $message = is_array($data) ? (string) ($data['message'] ?? $code) : "HTTP {$status}";
            throw new CofferException($status, $code, $message);
        }
        if (!is_array($data)) {
            throw new CofferException($status, 'invalid_response', 'response is not JSON');
        }
        return $data;
    }
}
