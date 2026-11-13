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
//      - setup-endpoint (Tumbler): user-chosen password, keys derived locally, recovery key printed
//        once, via the app's one-time setup endpoint (./tumbler.ts).
//      - bitwarden-register: claim via the app's API immediately after deploy (./nodewarden.ts).
//
// Implemented commands:
//   nodewarden-claim --url <worker url> [--username <name or email>] [--name <display name>] [--yes]
//   tumbler-setup-admin --url <worker url> [--username <name>] [--yes]
//     Setup token from TUMBLER_SETUP_TOKEN, or prompted (hidden).
//   Missing values are prompted for interactively. Passwords are always typed by the user
//   (hidden, twice); on non-TTY stdin they are read as lines, e.g. for CI.

import { parseArgs } from "node:util";
import { APPS } from "./apps.ts";
import { MIN_MASTER_PASSWORD_LENGTH, validateMasterPassword } from "./lib/password.ts";
import { CancelledError, readHidden } from "./lib/tty.ts";
import { assertClaimable, ClaimError, claimFirstAdmin, loginFromUsername, printClaimSummary } from "./nodewarden.ts";
import { assertSetupNeeded, normalizeTumblerUsername, printTumblerSummary, setupTumblerAdmin } from "./tumbler.ts";

const info = (msg: string) => process.stderr.write(`${msg}\n`);

const USAGE = `Usage:
  ./install.sh nodewarden-claim [--url <worker url>] [--username <name or email>] [--name <display name>] [--yes]
  ./install.sh tumbler-setup-admin [--url <worker url>] [--username <name>] [--yes]

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
			await assertClaimable(url);
			const username =
				values.username ?? prompt("Admin login: a username (e.g. admin) or your own email (e.g. you@proton.me):", "admin")?.trim();
			if (!username) {
				console.error(USAGE);
				return 2;
			}
			const email = loginFromUsername(username, url);
			const name = values.name ?? prompt("Display name:", username.split("@")[0])?.trim();
			info(`\nAdmin login will be: ${email}`);
			info("Bitwarden clients sign in with an email-shaped login; no mail is sent to it.");
			const password = await readNewPassword(email);
			if (!values.yes && prompt("Create the admin account now? [y/N]")?.trim().toLowerCase() !== "y") {
				info("Aborted. Nothing was created.");
				return 1;
			}
			info("Deriving keys and registering the admin account…");
			const result = await claimFirstAdmin({ url, email, password, name: name || undefined });
			printClaimSummary(result);
			return 0;
		}
		case "tumbler-setup-admin": {
			const { values } = parseArgs({
				args: rest,
				options: { url: { type: "string" }, username: { type: "string" }, yes: { type: "boolean", short: "y" } },
			});
			const url = values.url ?? prompt("Tumbler URL:")?.trim();
			if (!url) {
				console.error(USAGE);
				return 2;
			}
			await assertSetupNeeded(url);
			const setupToken = process.env.TUMBLER_SETUP_TOKEN || (await readHidden("ADMIN_SETUP_TOKEN:"));
			const username = normalizeTumblerUsername(values.username ?? prompt("Admin username:", "admin")?.trim() ?? "");
			const password = await readNewPassword(username);
			if (!values.yes && prompt(`Create Tumbler admin "${username}" now? [y/N]`)?.trim().toLowerCase() !== "y") {
				info("Aborted. Nothing was created.");
				return 1;
			}
			info("Deriving keys and creating the admin account…");
			printTumblerSummary(await setupTumblerAdmin({ url, setupToken, username, password }));
			return 0;
		}
		default:
			console.error(USAGE);
			return command ? 2 : 1;
	}
}

async function readNewPassword(login: string): Promise<string> {
	info(
		`\nChoose the master password (${MIN_MASTER_PASSWORD_LENGTH}+ characters). A memorable passphrase works well,` +
			"\ne.g. four or more unrelated words. It cannot be recovered if forgotten.",
	);
	for (let attempt = 0; attempt < 3; attempt++) {
		const pw = await readHidden("Master password:");
		const err = validateMasterPassword(pw, login);
		if (err) {
			info(`  ${err}`);
			continue;
		}
		if ((await readHidden("Confirm master password:")) !== pw) {
			info("  Passwords do not match.");
			continue;
		}
		return pw;
	}
	throw new ClaimError("No valid master password entered. Nothing was created.");
}

try {
	process.exit(await main(process.argv.slice(2)));
} catch (e) {
	if (e instanceof ClaimError || e instanceof CancelledError) {
		console.error(`\n✖ ${e.message}`);
		process.exit(1);
	}
	throw e;
}
