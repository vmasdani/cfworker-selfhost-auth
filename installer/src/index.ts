// Installer entry point. Apps it can install: ./apps.ts
//
// Planned full flow (idempotent; re-running upgrades an existing install):
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
//      - bitwarden-register: claim via the app's API immediately after deploy (./nodewarden.ts).
//
// Implemented commands:
//   nodewarden-claim --url <worker url> [--username <name or email>] [--name <display name>] [--yes]
//   Missing values are prompted for interactively.

import { parseArgs } from "node:util";
import { APPS } from "./apps.ts";
import { ClaimError, claimFirstAdmin, loginFromUsername, printCredentialsOnce } from "./nodewarden.ts";

const USAGE = `Usage:
  ./install.sh nodewarden-claim [--url <worker url>] [--username <name or email>] [--name <display name>] [--yes]

Full interactive install is not implemented yet. Planned apps: ${APPS.map((a) => a.id).join(", ")}`;

async function main(argv: string[]): Promise<number> {
	const [command, ...rest] = argv;
	switch (command) {
		case "nodewarden-claim": {
			const { values } = parseArgs({
				args: rest,
				options: {
					url: { type: "string" },
					username: { type: "string" },
					name: { type: "string" },
					yes: { type: "boolean", short: "y" },
				},
			});
			const url = values.url ?? prompt("NodeWarden URL:")?.trim();
			if (!url) {
				console.error(USAGE);
				return 2;
			}
			const username =
				values.username ?? prompt("Admin login: a username (e.g. admin) or your own email (e.g. you@proton.me):", "admin")?.trim();
			if (!username) {
				console.error(USAGE);
				return 2;
			}
			const email = loginFromUsername(username, url);
			const name = values.name ?? prompt("Display name:", username.split("@")[0])?.trim();
			console.error(`\nAdmin login will be: ${email}`);
			console.error("Bitwarden clients sign in with an email-shaped login; no mail is sent to it.");
			if (!values.yes && prompt("Create the admin account now? [y/N]")?.trim().toLowerCase() !== "y") {
				console.error("Aborted. Nothing was created.");
				return 1;
			}
			console.error("Deriving keys and registering the admin account…");
			const result = await claimFirstAdmin({ url, email, name: name || undefined });
			printCredentialsOnce(result);
			return 0;
		}
		default:
			console.error(USAGE);
			return command ? 2 : 1;
	}
}

try {
	process.exit(await main(process.argv.slice(2)));
} catch (e) {
	if (e instanceof ClaimError) {
		console.error(`\n✖ ${e.message}`);
		process.exit(1);
	}
	throw e;
}
