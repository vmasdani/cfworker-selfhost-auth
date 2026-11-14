# Agent guidelines

Rules for AI agents and contributors working in this repository.

## Tooling
- **Bun** is the package manager, script runner and test runner (`bun install`, `bun run`, `bun test`).
- **Worker code runs on workerd, not Bun.** Do not use Bun-only APIs (`Bun.*`, `bun:*`) under `apps/*/worker/` or in packages imported by Workers. Use Web APIs and WebCrypto.
- **Cloudflare: use the `cf` CLI.** Projects are configured with `cloudflare.config.ts`. Do not add `wrangler.jsonc`/`wrangler.toml`. For commands `cf` does not support yet (live logs, single secrets), use `npx wrangler ... --name <worker>` without adding Wrangler to the project.
- Discover `cf` commands with `cf cli search "<task>"` and preview with `--dry-run`. Do not guess flags from memory.

## Provisioning and deployment
- **The installer is the source of truth.** Provision, migrate and deploy through `./install.sh` (non-interactive: `--yes --account <id> --apps <list>`). Do not improvise resource creation with ad-hoc `cf` commands.
- **Never delete Cloudflare resources** (D1 databases, R2 buckets, Workers, secrets) unless the user explicitly asks for that specific resource in the current conversation. In non-interactive sessions, `cf` destructive commands without `--force` print `Aborted.` and still exit 0; do not treat exit 0 as success.
- **Third-party apps** (e.g. NodeWarden) are registered in `installer/src/apps.ts`, never vendored. Pin a full commit SHA with the tag; bump it only after reviewing the upstream diff. They deploy with their own config (NodeWarden ships `wrangler.toml`, so it uses Wrangler via `npx`, in its own clone directory).
- **Migrations are append-only.** Never edit an applied migration in `apps/*/migrations/`; add a new numbered file.
- Ask before `cf deploy` to a production account.

## Secrets and user data
- **Never print, log, commit or send secrets**: TOTP secrets, passwords, recovery keys, session tokens, `SERVER_SECRET`, API tokens.
- Authenticator backups/exports (e.g. Proton or Google exports) contain plaintext TOTP secrets. Do not read their values; inspect structure only with redaction. Never commit them (see `.gitignore`).
- Credentials generated at account creation are shown to the user exactly once and never stored in plaintext.

## Security invariants (do not weaken)
- Zero-knowledge: encryption and key derivation happen client-side; the server stores only ciphertext and verifiers.
- No open sign-up: accounts come only from the installer (first admin) or single-use, expiring invite links.
- No dependency on a single third-party identity provider. Default auth is strong password + TOTP 2FA.
- Strict CSP (`apps/*/public/_headers`), no third-party runtime scripts or CDNs.
- Each app has its own Worker and its own D1 database. Share code via `packages/`, never data.
  Accounts live in `packages/worker-accounts`; an app's cookie name and `aadPrefix` must never change once deployed.
- Coffer: the SDK files in `apps/coffer/sdk/` must stay single-file and standard-library-only, and byte-compatible with
  `apps/coffer/web/lib/keys.ts` (same HKDF info and AAD strings). Change the protocol only with a new version prefix
  (`coffer/v2/...`) and run `scripts/sdk-matrix.ts` with every toolchain before committing SDK changes.
  Keep `sdk/PORTING.md` (the AI-agent porting task) and `sdk/test-vectors.json` in step with the protocol.

## Code
- TypeScript, strict. `bun run typecheck` and `bun test` must pass before committing.
- Crypto and TOTP code must have tests, including RFC 6238 test vectors.
- Keep dependencies minimal; justify any new runtime dependency.
