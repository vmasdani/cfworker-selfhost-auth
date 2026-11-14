# cfworker-selfhost-auth

Self-hosted authentication and secrets tools that run on Cloudflare Workers + D1.

| App | Status | Description |
|---|---|---|
| [Tumbler Authenticator](apps/tumbler) | working: local vault, QR scan, import/export, accounts + encrypted sync; installer ready | Offline-capable PWA TOTP authenticator with optional end-to-end encrypted sync |
| [Coffer](apps/coffer) | working: projects, environments, members, client IDs, REST API, one-file clients for TS/JS, Go, C#, PHP; installer ready | Zero-knowledge secrets manager (Infisical-like). See [docs/coffer.md](docs/coffer.md) |
| [NodeWarden](https://github.com/shuaiplus/NodeWarden) (third-party) | installer: KV variant | Bitwarden-compatible password manager server on Workers + D1. Installed from upstream at a pinned commit; LGPL-3.0; not affiliated with Bitwarden |

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
./install.sh                     # interactive
./install.sh --profile <cf profile> --apps tumbler --domain tumbler.example.com
./install.sh --profile <cf profile> --apps coffer --domain coffer.example.com
./install.sh ... --dry-run       # check everything, build, create/upload nothing
```

Requires [Bun](https://bun.sh), Node.js 22.18+ and the [`cf` CLI](https://developers.cloudflare.com/cf/) (`npm install --global cf`), signed in (`cf auth login`, optionally `--profile <name>`).

For Tumbler and Coffer the installer:

1. picks the `cf` profile and Cloudflare account;
2. checks the custom domain: its zone must be in the account and the hostname must have no DNS records (leave it blank to use workers.dev);
3. reuses the D1 database (`tumbler-db`, `coffer-db`) by name, or creates it after asking;
4. applies D1 migrations;
5. sets Worker secrets: `SERVER_SECRET` only if missing (it is never rotated: every login depends on it) and a fresh one-time `ADMIN_SETUP_TOKEN`. Values pass through a private temp file to `cf deploy --secrets-file` and are never printed;
6. deploys and waits until the site answers (a new custom domain's certificate can take a few minutes);
7. if the server has no users yet, asks for the first admin's username and password and prints the recovery key once.

Re-running it upgrades in place. It never deletes anything.

For NodeWarden (`--apps nodewarden`, attachments in KV by default; `--variant r2` is not automated yet) the installer clones the commit pinned in `installer/src/apps.ts`, verifies it, runs `npm ci --ignore-scripts`, reuses or creates `nodewarden-db` and the KV namespace, writes its own Wrangler config next to upstream's (resource IDs, and workers.dev off with a custom domain), sets `JWT_SECRET` only if missing, deploys with Wrangler, and then claims the admin account in the same run. NodeWarden deploys with Wrangler, which has its own login: run `npx wrangler login` once (choose the same Cloudflare account), or set `CLOUDFLARE_API_TOKEN` to a token you created.

To claim NodeWarden's admin separately (e.g. after a manual deploy), do it immediately: NodeWarden makes the first registered account the admin, so do this immediately:

```sh
./install.sh nodewarden-claim --url https://nodewarden.<you>.workers.dev
```

It asks for the admin login (a username such as `admin`, which becomes `admin@<worker host>`, or your own email such as `you@proton.me`) a display name, and a master password you choose (typed hidden, twice; 12+ characters, a memorable passphrase works well). It derives the keys locally, registers the account, verifies it by logging in, and never prints or stores the password. It refuses if the instance already has an account.

To create Tumbler's or Coffer's first admin separately (e.g. after a manual deploy):

```sh
TUMBLER_SETUP_TOKEN=<token> ./install.sh setup-admin --app tumbler --url https://tumbler.<you>.workers.dev
COFFER_SETUP_TOKEN=<token>  ./install.sh setup-admin --app coffer  --url https://coffer.<you>.workers.dev
```

You choose the username and password; keys are derived locally and the recovery key is printed once. The setup endpoint works only while the server has no users. Everyone else joins with single-use invite links (Tumbler: Settings → Sync → Invite users; Coffer: Account → Invite users).

## Coffer in your apps

Create a client ID for one environment (project → Access), put the three values in your app's environment, and add one file from project → Integrate (it has your server URL filled in). No packages:

```sh
COFFER_URL=https://coffer.example.com
COFFER_CLIENT_ID=cfi_...
COFFER_CLIENT_SECRET=cfs_...
```

```ts
const coffer = Coffer.fromEnv();            // coffer.ts: Node 20+, Bun, Deno, Workers
const all = await coffer.listAllSecrets();  // { DATABASE_URL: "...", ... }
const db = await coffer.getSecret("DATABASE_URL");
await coffer.writeSecret("API_TOKEN", "s3cr3t");
```

Same API in [`coffer.go`](apps/coffer/sdk/coffer.go) (Go 1.24+), [`Coffer.cs`](apps/coffer/sdk/Coffer.cs) (.NET 8+) and [`Coffer.php`](apps/coffer/sdk/Coffer.php) (PHP 8.1+). Each file decrypts locally; the server only stores and serves ciphertext. Protocol and threat model: [docs/coffer.md](docs/coffer.md).

## Development

```sh
bun install
bun run dev:tumbler     # local dev server (cf dev)
bun run dev:coffer
bun run typecheck
bun test

# Tumbler API end to end, against a local server with an empty database
cd apps/tumbler
cp .dev.vars.example .dev.vars          # then put random values in it
bun run build && bunx vite preview --port 4173 &
curl -s localhost:4173/api/setup >/dev/null   # creates the local D1 file
bun run db:migrate:local
bun run test:api http://localhost:4173 "$(grep ADMIN_SETUP_TOKEN .dev.vars | cut -d= -f2-)"
bun run --cwd apps/tumbler icons   # regenerate logo + PWA icons into apps/tumbler/public

# Coffer API + TS SDK end to end (empty local database; same .dev.vars setup)
cd apps/coffer && bun run dev -- --port 5180 &
curl -s localhost:5180/api/setup >/dev/null && bun run db:migrate:local
bun run test:api http://localhost:5180 "$(grep ADMIN_SETUP_TOKEN .dev.vars | cut -d= -f2-)"
# or every SDK (TS, Go, C#, PHP; missing toolchains are skipped):
bun run scripts/sdk-matrix.ts http://localhost:5180 "$(grep ADMIN_SETUP_TOKEN .dev.vars | cut -d= -f2-)"
```

Repository layout:

```
apps/tumbler/        Tumbler Authenticator (Vite + Preact PWA, Hono API Worker, D1 migrations)
apps/coffer/         Coffer secrets manager (dashboard, API Worker, migrations, sdk/ one-file clients)
packages/crypto/     KDF, AES-256-GCM, key wrapping
packages/totp/       RFC 6238 TOTP engine
packages/importers/  Proton Authenticator, Google Authenticator, otpauth URI import/export
packages/server-kit/ sessions, rate limiting, validation, SERVER_SECRET keys
packages/worker-accounts/ accounts for app Workers: setup, login + TOTP, invites, recovery (Hono)
packages/ui/         shadcn/ui components ported to Preact, shared by the apps
installer/           interactive installer (run via ./install.sh)
```

Agents and contributors: read [AGENTS.md](AGENTS.md).
