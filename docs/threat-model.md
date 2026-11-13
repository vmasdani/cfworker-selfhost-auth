# Threat model (draft)

## Assets
- TOTP secrets (Tumbler), application secrets (secrets manager).
- Master passwords, PINs, recovery keys, vault keys.
- Session tokens.

## Design
- Vault key: random 256-bit key, generated client-side. Entries are encrypted with AES-256-GCM.
- Master password: KDF (PBKDF2-SHA256 600k or Argon2id) on the client derives two separate keys: an encryption key that wraps the vault key, and an auth key sent to the server. The server stores `HMAC(SERVER_SECRET, auth key)`, never the password or encryption key.
- Recovery key: random, shown once at account creation. Wraps a second copy of the vault key.
- PIN (8+ digits): local-only second wrap of the vault key. Wiped after 5 failed attempts, falling back to the master password.
- Account login 2FA: TOTP. The secret is encrypted at rest with `SERVER_SECRET`.
- Pre-login returns a decoy salt (`HMAC(SERVER_SECRET, username)`) for unknown usernames, so usernames cannot be enumerated.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| D1 database leaked | Only ciphertext and HMAC verifiers stored | Offline guessing of weak passwords; enforce strong passwords |
| Worker code compromised / Cloudflare account takeover | Hardware key on Cloudflare account, scoped API tokens | Attacker can serve malicious JS that captures passwords. Same as any web vault |
| Online password guessing | Rate limiting, lockout, TOTP 2FA | — |
| Stolen unlocked device | Auto-lock on idle/hidden, clipboard auto-clear | Data exposed while unlocked |
| Stolen locked device, PIN enabled | KDF on PIN, attempt limit in app | Attempt limit is app-enforced only; a disk copy allows offline brute force of the PIN. Use long PINs or master password only on high-risk devices |
| XSS / supply chain | Strict CSP, no third-party scripts, minimal dependencies | Compromised npm dependency at build time |
| Third-party identity provider outage or account ban | No dependency on external IdPs by default | — |
| Lost password and recovery key | — | Synced vault unrecoverable by design; local unlocked copies remain |
