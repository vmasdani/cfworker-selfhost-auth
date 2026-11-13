# cfworker-selfhost-auth

Self-hosted authentication and secrets tools that run on Cloudflare Workers + D1.

| App | Status | Description |
|---|---|---|
| [Tumbler Authenticator](apps/tumbler) | local vault working, sync pending | Offline-capable PWA TOTP authenticator with optional end-to-end encrypted sync |
| Secrets manager | planned | Infisical-like secrets management on Workers |
| [NodeWarden](https://github.com/shuaiplus/NodeWarden) (third-party) | installer support planned | Bitwarden-compatible password manager server on Workers + D1. Installed from upstream at a pinned commit; LGPL-3.0; not affiliated with Bitwarden |

Third-party apps are not vendored into this repository. The installer fetches them at the commit pinned in [`installer/src/apps.ts`](installer/src/apps.ts) and deploys them with their own tooling.

## Principles

### Secure by default
- **Zero-knowledge.** Encryption happens on the client. The server stores only ciphertext and verifiers; it never sees TOTP secrets, vault keys, or master passwords.
- **Safe defaults, no opt-in required.** Strict CSP, no third-party scripts, auto-lock, clipboard auto-clear, rate-limited login, credentials shown once and never logged.
- **No open sign-up.** Accounts are created only by the installer (first admin) or by single-use, expiring invite links.
- **Recovery is explicit.** Every account gets a recovery key, shown once at creation. Lose both the password and the recovery key and the synced vault is unrecoverable, by design.

### Least dependent on single authentication providers
"Sign in with Google" ties your account to someone else's account. If the provider account is suspended, locked, or deleted, every account that depends on it goes with it. Google dies, your account dies.

So the default does not depend on any third-party identity provider:

- **Default: a strong password + TOTP 2FA.** This is more than enough for a self-hosted app with a small user base, and it keeps working whatever happens to any external provider.
- **Save credentials in a password manager** such as Bitwarden or Proton Pass, and the recovery key somewhere offline.
- External identity providers (OIDC, Cloudflare Access) may be added later as an **optional extra layer** in front, never as the only way in.

### Local-first
Apps work without an account. Tumbler runs fully offline from a local encrypted vault; signing in later only adds sync.

## Why Cloudflare Workers fit self-hosted auth

- **Smaller blast radius if breached.** Each app is its own Worker in a V8 isolate with its own D1 database. No shell, no SSH, no OS to patch, nothing persistent for an attacker to sit on, and no lateral movement between apps. Because data is end-to-end encrypted, a leaked D1 database yields only ciphertext.
- **Low invocation workload.** Authenticator sync and secret fetches are rare requests, unlike a transaction ledger or social feed. This fits comfortably within the Workers free tier.
- **Lean, scales to zero.** Resources are used only when a request arrives. No 24/7 VPS, no idle cost, no open ports to scan.
- **Behind Cloudflare.** DDoS protection, TLS, WAF, Turnstile, rate limiting and optional Access come with the platform. Not 100% fault-tolerant, but far more resilient than a self-managed on-prem server or VPS.
- **Backups.** D1 Time Travel provides point-in-time restore.

### Caveats
- **Your Cloudflare account is the root of trust.** Whoever controls it controls the JavaScript the app serves, and could ship code that captures master passwords. This is the same risk as any web vault. Protect the Cloudflare account with a hardware security key and use scoped API tokens.
- **Vendor lock-in and D1 limits.** Keep regular exports so you can leave or recover.

See [docs/threat-model.md](docs/threat-model.md).

## Install

```sh
./install.sh
```

Requires [Bun](https://bun.sh), Node.js 22.18+ and the [`cf` CLI](https://developers.cloudflare.com/cf/) (`npm install --global cf`). The installer selects the Cloudflare account and apps, reuses or creates D1 databases, applies migrations, deploys, and creates the first admin. The full flow is not implemented yet.

Available now: claim the NodeWarden admin account right after deploying it. NodeWarden makes the first registered account the admin, so do this immediately:

```sh
./install.sh nodewarden-claim --url https://nodewarden.<you>.workers.dev
```

It asks for the admin login (a username such as `admin`, which becomes `admin@<worker host>`, or your own email such as `you@proton.me`) a display name, and a master password you choose (typed hidden, twice; 12+ characters, a memorable passphrase works well). It derives the keys locally, registers the account, verifies it by logging in, and never prints or stores the password. It refuses if the instance already has an account.

## Development

```sh
bun install
bun run dev:tumbler     # local dev server (cf dev)
bun run typecheck
bun test
bun run --cwd apps/tumbler icons   # regenerate logo + PWA icons into apps/tumbler/public
```

Repository layout:

```
apps/tumbler/        Tumbler Authenticator (Vite + Preact PWA, Hono API Worker, D1 migrations)
packages/crypto/     KDF, AES-256-GCM, key wrapping
packages/totp/       RFC 6238 TOTP engine
packages/importers/  Proton Authenticator, Google Authenticator, otpauth URI import/export
packages/server-kit/ sessions, rate limiting, invites, D1 helpers
installer/           interactive installer (run via ./install.sh)
```

Agents and contributors: read [AGENTS.md](AGENTS.md).
