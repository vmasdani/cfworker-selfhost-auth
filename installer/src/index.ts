// Interactive installer (not implemented yet). Apps it can install: ./apps.ts
//
// Planned flow (idempotent; re-running upgrades an existing install):
//   1. Verify `cf auth whoami`; prompt `cf auth login` if needed. External apps that
//      deploy with Wrangler get the same account via CLOUDFLARE_API_TOKEN/ACCOUNT_ID.
//   2. List accounts, select one.
//   3. Select apps to install (Tumbler, NodeWarden, ...) and a variant where offered.
//   4. External apps: clone the pinned commit into .installer/apps/<id>, verify the commit hash,
//      `npm ci`. Never run upstream code from an unpinned ref.
//   5. For each D1/R2/KV resource: look up by name, reuse or create. Never delete.
//   6. Generate missing secrets (never printed), apply migrations, deploy.
//   7. First admin, credentials printed ONCE with a warning to save them in a password manager:
//      - installer-bootstrap: generate credentials + recovery key locally, run the KDF locally,
//        insert into D1.
//      - bitwarden-register: register via the app's API immediately after deploy. Abort with a
//        warning if an account already exists that the installer did not create.
//
// Non-interactive: --yes --account <id> --apps tumbler,nodewarden [--variant nodewarden=kv]

import { APPS } from "./apps.ts";

console.error(`installer: not implemented yet. Planned apps: ${APPS.map((a) => a.id).join(", ")}`);
process.exit(1);
