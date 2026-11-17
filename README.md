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

## Standalone mode (Bun + SQLite, no Cloudflare)

Tumbler and Coffer also run as plain Bun processes with a local SQLite file, for a VPS or home server. The same Worker code runs unchanged: `packages/standalone` gives it a D1-compatible database over `bun:sqlite` (WAL, foreign keys on, `batch` as one transaction), applies `migrations/` on every start, and serves the built web app with its `_headers` (CSP and the rest), SPA fallback, ETags and precompressed brotli/gzip.

```sh
bun install
bun run build:standalone          # web apps into apps/<app>/dist
pm2 start ecosystem.config.cjs    # tumbler on 127.0.0.1:8701, coffer on 127.0.0.1:8702
pm2 save && pm2 startup           # start on boot
# without pm2:
bun run start:tumbler             # or: cd apps/tumbler && bun run .
```

On a small server, prefer systemd to pm2: the pm2 daemon and pm2-logrotate took about 167 MB next to a 58 MB Coffer process on a 2 GB box. [`deploy/coffer.service.example`](deploy/coffer.service.example) is a hardened unit (only the data directory is writable, logs in `journalctl -u coffer`); the same unit works for Tumbler with its own port, user and data directory.

- **HTTPS is required.** Sessions use a `__Host-` cookie, which browsers keep only over https (or on localhost). Put Caddy, nginx or Cloudflare Tunnel in front, and set `PUBLIC_URL` to the public origin (in `apps/<app>/.env`, or `TUMBLER_PUBLIC_URL=… COFFER_PUBLIC_URL=… pm2 start ecosystem.config.cjs`). It is used for the same-origin (CSRF) check.
- **Client IPs** (for login rate limits) come from the rightmost `X-Forwarded-For` entry when bound to loopback (the default `HOST=127.0.0.1`), or from `CLIENT_IP_HEADER` (e.g. `CF-Connecting-IP` behind Cloudflare Tunnel). Set `TRUST_PROXY=0` if nothing in front sets these headers.
- **Secrets.** On first start `SERVER_SECRET` is generated into `$DATA_DIR/server-secret` (mode 0600; default `data/<app>/` under the repo with pm2, `./data` otherwise). It never rotates: every login verifier depends on it, so back it up together with the database. While the server has no users, a fresh one-time setup token is written to `$DATA_DIR/admin-setup-token` on every start; the log prints the command that creates the first admin, e.g.

  ```sh
  TUMBLER_SETUP_TOKEN="$(cat data/tumbler/admin-setup-token)" ./install.sh setup-admin --app tumbler --url https://tumbler.example.com
  ```

  The token file is deleted on the next start after the first admin exists.
- **One process per app.** SQLite has one writer: keep pm2 in fork mode with one instance (as in `ecosystem.config.cjs`), or one systemd service per app. On SIGINT/SIGTERM the server finishes open requests and closes the database.
- **Backups:** `sqlite3 data/tumbler/tumbler.sqlite ".backup tumbler-$(date +%F).sqlite"` (safe while running), plus `server-secret`.

All settings: [`packages/standalone/src/server.ts`](packages/standalone/src/server.ts). The end-to-end API checks run against it too: `bun run test:api http://localhost:8701 "$(cat data/tumbler/admin-setup-token)"` on an empty database.

## Rust backends (experimental, not deployed)

The [`rust-poc`](../../tree/rust-poc) branch holds a Rust port of the Tumbler and Coffer backends: a Worker built with [workers-rs](https://github.com/cloudflare/workers-rs) (wasm32, D1) and a native standalone binary (hyper, bundled SQLite). It is byte-compatible with the TypeScript backends (same routes, SQL, status codes, JSON, cookies, stored formats), so either one runs on the other's database. The web apps and SDKs stay TypeScript. It was a proof of concept: a separate `tumbler-rs` Worker on a copy of the database passed the end-to-end tests, Coffer passed the SDK matrix (including the C# client), and both are removed again. It is not merged into `main`. Details: `docs/rust-port.md` on that branch.

**Not worth it for a single-user, self-hosted install.** The TypeScript backends stay the reference. Caveats:

- **Two implementations.** Every backend change has to be made in both and pass `scripts/rust-parity.ts`. That roughly doubles backend work, for people and for AI agents. Keep one backend per app.
- **Little gain on Workers.** The apps mostly wait on D1, so requests are not faster. Crypto runs in wasm (RustCrypto) instead of native WebCrypto, and the Worker grows to about 600 KB.
- **The standalone gain is real but small.** Rust Coffer: 3.6 MB RSS against 58 MB for Bun, 27 ms against 54 ms for 300 requests. Most of the memory saving on a small box comes from dropping pm2 (about 167 MB), which systemd does for the Bun server too.
- **Toolchain.** rustup, the `wasm32-unknown-unknown` and `x86_64-unknown-linux-musl` targets, `worker-build` (its version must match the `worker` crate), and a musl C compiler for the bundled SQLite. Builds are slower than `bun run build`.
- **No shared types** between the TypeScript web apps and a Rust API; generate them (e.g. `ts-rs`) if the port is ever adopted.
- **Secrets cannot be read back.** A Worker's `SERVER_SECRET` is write-only, so a second Worker (like `tumbler-rs`) gets its own secret and copied accounts cannot log in there. Replacing the code of the same Worker keeps its secret.
- Migrations stay in `d1_migrations` (cf CLI and the Bun server use it), not `sqlx`'s own table.

Rust pays off for CPU-bound work: native servers with tight memory or latency limits, or Workers doing heavy compute (image processing, parsing, compression, KDFs WebCrypto lacks).

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

Language not listed? Project → Integrate → **Other** gives a ready-made task for an AI coding agent (Claude Code, Codex, Cursor…): the protocol ([`sdk/PORTING.md`](apps/coffer/sdk/PORTING.md)), offline [test vectors](apps/coffer/sdk/test-vectors.json) and the TypeScript client as reference, with instructions to test before claiming it works.

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
packages/standalone/ standalone mode: Bun server, D1-compatible bun:sqlite adapter, static files (Bun-only)
packages/ui/         shadcn/ui components ported to Preact, shared by the apps
installer/           interactive installer (run via ./install.sh)
ecosystem.config.cjs pm2 processes for standalone mode
deploy/              systemd units for standalone mode
```

Agents and contributors: read [AGENTS.md](AGENTS.md).
