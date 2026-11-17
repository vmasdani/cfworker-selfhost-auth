# Rust port (proof of concept)

Status: experimental and not deployed. The POC ran in November 2026 and its deployments were removed; the
TypeScript backends are the reference. Why it was not adopted: [README → Rust backends](../README.md#rust-backends-experimental-not-deployed).

The Tumbler and Coffer backends also exist in Rust, next to the TypeScript Workers. The web apps, the
client-side crypto and the SDKs are unchanged. The Rust code is a port, not a redesign: same routes,
SQL, status codes, JSON, cookies, rate limits and stored data, so either implementation can run on the
other's database.

| Path | What |
|---|---|
| `crates/core` | crypto (RustCrypto), TOTP, validation, sessions, rate limits, accounts, the `/api` shell, the D1 adapter (wasm32) |
| `crates/standalone` | native server: SQLite (rusqlite, bundled), static files, hyper on a single-threaded tokio runtime |
| `apps/<app>/rs` | the app's routes; builds as a Worker (wasm32) and as the native binary `<app>-server` |
| `scripts/rust-parity.ts` | TS and Rust standalone servers, same requests, diffed; then each runs on the other's database |
| `scripts/standalone-compare.ts` | live server against a candidate on a copy of its data, read-only requests only |

## Build

Toolchain: `rustup`, targets `wasm32-unknown-unknown` and `x86_64-unknown-linux-musl`, `cargo install worker-build`.

```sh
cargo test --workspace
cargo build --release -p tumbler-rs -p coffer-rs --bins          # native, for local runs and parity
bun run build:standalone && bun scripts/rust-parity.ts tumbler     # and: coffer
```

Static binary for a server (no glibc dependency; needs a musl C compiler for the bundled SQLite):

```sh
CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-musl -p coffer-rs --bin coffer-server
```

The binary embeds the migrations (in the `d1_migrations` table, like cf and the Bun server) and reads the
same environment variables, `.env` files and `$DATA_DIR` files (`<app>.sqlite`, `server-secret`,
`admin-setup-token`) as `packages/standalone`. It serves `dist/` next to the executable, or `STATIC_DIR`.

## Tumbler on Workers: `tumbler-rs`

A separate Worker on a copy of the database, built from the same `apps/tumbler/cloudflare.config.ts`:

```sh
(cd apps/tumbler/rs && worker-build --release)
cd apps/tumbler
TUMBLER_RUST=1 TUMBLER_D1_ID=<tumbler-rs-db id> TUMBLER_DOMAIN=<domain> CLOUDFLARE_ACCOUNT_ID=<account> cf build
cf deploy --prebuilt --mode production
```

`TUMBLER_RUST=1` switches the Worker name to `tumbler-rs` and the database to `tumbler-rs-db` (the POC created
the copy with `d1 export` and `d1 execute --file`, then deleted both); never set it for the production Worker. A Worker secret cannot be read back, so the copy has its own SERVER_SECRET:
accounts copied from the original cannot log in there (their verifiers use the original secret).

## Coffer standalone: cutover from Bun + pm2

Not done: staging keeps the Bun server, moved from pm2 to systemd (`deploy/coffer.service.example`), which
gives most of the memory saving. The runbook below stays for reference.

Measured on a 2 GB staging box with the same data: Rust 3.6 MB RSS against 58 MB for Bun, plus 167 MB for
the pm2 daemon and pm2-logrotate; 300 sequential requests in 27 ms against 54 ms. There is no mature Rust
replacement for pm2; systemd is the lean option (`deploy/coffer-rs.service.example`).

1. Back up while live (consistent with WAL): `VACUUM INTO` from a read-only connection, plus `server-secret`.
2. Copy the binary and `dist/` to `/opt/coffer/app-rs`. Start it on a spare port against a copy of the data
   directory and run `scripts/standalone-compare.ts` against the live server. Stop it; delete the copy.
3. Cutover (seconds of downtime; SDK clients that cache, such as alphazeta's `CofferStore`, ride it out):
   `pm2 stop coffer && pm2 save` as the `coffer` user, then `systemctl enable --now coffer-rs`.
   Check `/api/health` locally and through the public URL, then a real SDK read from a client.
4. Once stable: `systemctl disable --now pm2-coffer`.

Rollback: `systemctl stop coffer-rs && pm2 start coffer` (the user `coffer`'s pm2). The schema is shared,
so the TS server opens the database the Rust one wrote.
