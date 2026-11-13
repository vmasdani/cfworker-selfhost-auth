// Interactive installer (not implemented yet).
//
// Planned flow (idempotent; re-running upgrades an existing install):
//   1. Verify `cf auth whoami`; prompt `cf auth login` if needed.
//   2. List accounts, select one.
//   3. Select apps to install (tumbler, ...).
//   4. For each D1/R2 resource: look up by name, reuse or create. Never delete.
//   5. Apply D1 migrations, set secrets, deploy.
//   6. Bootstrap the first admin: generate credentials + recovery key locally,
//      run the KDF locally, insert into D1, print them ONCE.
//
// Non-interactive: --yes --account <id> --apps tumbler

console.error("installer: not implemented yet");
process.exit(1);
