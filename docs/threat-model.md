# Threat model

## Assets
- TOTP secrets (Tumbler), application secrets (Coffer; its design and threats: [coffer.md](coffer.md)).
- Master passwords, PINs, recovery keys, vault keys.
- Session tokens.

## Design
- Vault key: random 256-bit key, generated client-side. Entries are encrypted with AES-256-GCM.
- Master password: PBKDF2-SHA256 (600k) on the client, then HKDF into two separate keys: a wrap key that encrypts the vault key, and an auth key sent to the server. The server stores `HMAC(SERVER_SECRET, auth key)`, never the password or wrap key. The server rejects KDF parameters below 100k iterations.
- Recovery key: 160 random bits, shown once at account creation. HKDF gives a second wrap key (wraps another copy of the vault key) and a recovery auth key (server keeps its HMAC). Using it sets a new password, turns off login TOTP and signs out every session.
- Linking: after sign-in the account password is the device's master password. Joining with an invite reuses the device's vault key; signing in to an account with a different vault key re-encrypts local entries under the account key and removes the PIN (it wrapped the old key).
- Sessions: 256-bit random token in a `__Host-` cookie (HttpOnly, Secure, SameSite=Strict), stored as SHA-256, 30-day sliding expiry. Password change signs out other sessions.
- CSRF: state-changing requests must be same-origin (Origin header) and JSON.
- Accounts: no open sign-up. First admin through a setup endpoint that needs `ADMIN_SETUP_TOKEN` and works only while there are no users; everyone else through single-use invite links (24 h, only the token hash is stored, consumed in the same transaction that creates the user).
- Sync: one ciphertext row per entry, bound to its id with AES-GCM associated data. Last-write-wins per entry by client time, decided atomically in SQL; timestamps more than 24 h in the future are rejected.
- PIN (8+ digits): local-only second wrap of the vault key. Wiped after 5 failed attempts, falling back to the master password.
- Account login 2FA: TOTP. The secret is encrypted at rest with `SERVER_SECRET`.
- Pre-login returns a decoy salt (`HMAC(SERVER_SECRET, username)`) for unknown usernames, so usernames cannot be enumerated.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| D1 database leaked | Only ciphertext and HMAC verifiers stored | Offline guessing of weak passwords; enforce strong passwords |
| Worker code compromised / Cloudflare account takeover | Hardware key on Cloudflare account, scoped API tokens | Attacker can serve malicious JS that captures passwords. Same as any web vault |
| Online password guessing | Per-username and per-IP failure limits (D1), optional login TOTP with replay protection | A correct password with a missing TOTP code is distinguishable from a wrong password |
| Stolen session cookie | HttpOnly + SameSite=Strict, sign out, password change revokes other sessions | Session works until it expires or is revoked; the vault stays encrypted without the password |
| Malicious or compromised admin | Admin cannot read anyone's vault (zero-knowledge); can only create/revoke invites | A server operator can serve modified JavaScript (see Worker compromise) |
| Device clock wrong | Server rejects timestamps > 24 h ahead | A device slightly ahead can win a concurrent edit of the same entry |
| Stolen unlocked device | Auto-lock on idle/hidden, clipboard auto-clear | Data exposed while unlocked |
| Stolen locked device, PIN enabled | KDF on PIN, attempt limit in app | Attempt limit is app-enforced only; a disk copy allows offline brute force of the PIN. Use long PINs or master password only on high-risk devices |
| XSS / supply chain | Strict CSP, no third-party scripts, minimal dependencies | Compromised npm dependency at build time |
| Third-party identity provider outage or account ban | No dependency on external IdPs by default | — |
| Lost password and recovery key | — | Synced vault unrecoverable by design; local unlocked copies remain |
