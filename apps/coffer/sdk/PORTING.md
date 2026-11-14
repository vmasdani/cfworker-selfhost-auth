# Task: write a Coffer client for __LANGUAGE__

You are an AI coding agent. Write a Coffer client in __LANGUAGE__ for the project you are working in. Coffer is a
self-hosted, zero-knowledge secrets manager at __COFFER_URL__. The client must encrypt and decrypt locally: the server
only stores ciphertext and never sees secret names, values, the client secret or any key.

## Requirements

- **One file**, named idiomatically (e.g. `coffer.py`, `Coffer.java`, `coffer.rb`, `coffer.rs`).
- **Standard library only.** If the language's standard library has no AES-256-GCM, HKDF-SHA256 or HMAC-SHA256, use the
  single most common, well-maintained crypto package for it (e.g. Python `cryptography`, Rust `aes-gcm` + `hkdf` +
  `hmac` + `sha2`), say which one and why at the top of the file, and add nothing else. Never implement AES or GCM by
  hand. Never use ECB, CBC or a fixed IV for encryption.
- **Configuration from the environment**: `COFFER_CLIENT_ID`, `COFFER_CLIENT_SECRET`, and optional `COFFER_URL`
  (default `__COFFER_URL__`). Provide a `from_env()`-style constructor and a constructor taking the three values.
- **API** (idiomatic names and async style for the language):
  - `list_all_secrets()` → map of name → value
  - `get_secret(name)` → value, or null/None/absent when the server answers 404
  - `write_secret(name, value)` → new version number (needs a read-write client ID; 403 otherwise)
  - `delete_secret(name)` → true if deleted, false if it did not exist
  - `identity()` → clientId, scope, projectId, project, envId, environment
- Fetch `GET /api/v1/identity` once, lazily, and cache the derived keys for the client's lifetime (thread-safe if the
  language is commonly multi-threaded). Do not cache secret values.
- Errors: non-2xx responses carry JSON `{"error": code, "message": text}`; raise a dedicated error type with status,
  code and message. Never include the client secret or decrypted values in error messages or logs.
- Use HTTPS in production. Send `Content-Type: application/json` on requests with a body. 30 s timeout.

## Protocol (Coffer v1)

HKDF means HKDF-SHA256 (RFC 5869) with a salt of 32 zero bytes (the RFC's default for "no salt"; pass it explicitly
anyway) and 32 bytes of output. `utf8(x)` is the UTF-8 bytes of a string.

```
authKey  = HKDF(ikm = utf8(clientSecret), info = "coffer/v1/machine-auth")
wrapKey  = HKDF(ikm = utf8(clientSecret), info = "coffer/v1/machine-wrap")
header   = "Authorization: Bearer " + clientId + "." + base64(authKey)          (standard base64, with padding)

identity = GET /api/v1/identity  → { clientId, scope, projectId, project, envId, environment, wrappedKey: {iv, ct} }
envKey   = AES-256-GCM-decrypt(key = wrapKey, iv = base64dec(wrappedKey.iv), data = base64dec(wrappedKey.ct),
                               aad = utf8("coffer/v1/machine-key/" + clientId))
encKey   = HKDF(ikm = envKey, info = "coffer/v1/secret-enc")
indexKey = HKDF(ikm = envKey, info = "coffer/v1/secret-index")
mac(name)= lowercase hex of HMAC-SHA256(key = indexKey, data = utf8(name))
aad(mac) = utf8("coffer/v1/secret/" + envId + "/" + mac)
```

`ct` is the GCM ciphertext followed by the 16-byte tag (split them if the library wants the tag separately). IVs are
12 bytes. A secret's plaintext is the UTF-8 JSON object `{"name": name, "value": value}`.

| Call | Request | Response |
|---|---|---|
| list | `GET /api/v1/secrets` | `{ "secrets": [ { "mac", "iv", "ct", "version", "updatedAt" } ] }` |
| get | `GET /api/v1/secrets/<mac(name)>` | one row as above; 404 if missing |
| write | `PUT /api/v1/secrets/<mac(name)>` body `{ "iv", "ct" }` with a fresh random 12-byte IV | the stored row, with `version` |
| delete | `DELETE /api/v1/secrets/<mac(name)>` | `{ "deleted": true/false }` |

When decrypting a row: decrypt with `aad(row.mac)`, parse the JSON, and **check that `mac(parsed.name) == row.mac`**;
fail if it does not (the server must not be able to swap secrets between names).

## Tests you must write and run

1. **Offline test vectors** (below): derive authKey, the Authorization header, wrapKey, envKey (decrypt
   `wrappedKey`), encKey, indexKey, mac, and decrypt `secret` to `plaintextJson`. All must match exactly.
2. Encrypt `plaintextJson` with the fixed `secretIvB64` and compare with `expected.secret.ct` byte for byte.
3. If a test server and a client ID are available (ask the user; never invent credentials), run list → write →
   get → delete against it, and confirm that a secret written by your client is readable in the Coffer dashboard.

Report which tests ran and their results. Do not claim the client works if a test was skipped.
