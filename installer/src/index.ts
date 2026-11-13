// Installer entry point. Apps it can install: ./apps.ts
//
// Commands:
//   install (default)  Install or upgrade apps on a Cloudflare account (./install-tumbler.ts).
//       [--profile <cf profile>] [--account <id>] [--apps tumbler] [--domain <host> | --no-domain]
//       [--dry-run] [--yes]
//     Idempotent; re-running upgrades in place. Never deletes resources.
//   nodewarden-claim --url <worker url> [--username <name or email>] [--name <display name>] [--yes]
//   tumbler-setup-admin --url <worker url> [--username <name>] [--yes]
//     Setup token from TUMBLER_SETUP_TOKEN, or prompted (hidden).
// Missing values are prompted for interactively. Passwords are always typed by the user
// (hidden, twice); on non-TTY stdin they are read as lines, e.g. for CI.
//
// NodeWarden deploys with its own Wrangler config and is not automated yet: deploy it, then run
// nodewarden-claim right away.

import { parseArgs } from "node:util";
import { APPS } from "./apps.ts";
import { installTumbler, normalizeDomain } from "./install-tumbler.ts";
import { CfError, cfRun, whoami, type CfContext } from "./lib/cf.ts";
import { MIN_MASTER_PASSWORD_LENGTH, validateMasterPassword } from "./lib/password.ts";
import { CancelledError, readHidden } from "./lib/tty.ts";
import { assertClaimable, ClaimError, claimFirstAdmin, loginFromUsername, printClaimSummary } from "./nodewarden.ts";
import { assertSetupNeeded, normalizeTumblerUsername, printTumblerSummary, setupTumblerAdmin } from "./tumbler.ts";

const info = (msg: string) => process.stderr.write(`${msg}\n`);

const USAGE = `Usage:
  ./install.sh [install] [--profile <cf profile>] [--account <id>] [--apps tumbler]
               [--domain <host> | --no-domain] [--dry-run] [--yes]
  ./install.sh nodewarden-claim [--url <worker url>] [--username <name or email>] [--name <display name>] [--yes]
  ./install.sh tumbler-setup-admin [--url <worker url>] [--username <name>] [--yes]

Apps: ${APPS.map((a) => a.id).join(", ")} (install automates tumbler; nodewarden: deploy it, then nodewarden-claim)`;

async function main(argv: string[]): Promise<number> {
	const [first, ...others] = argv;
	const command = !first || first.startsWith("-") ? "install" : first;
	const rest = !first || first.startsWith("-") ? argv : others;
	switch (command) {
		case "install":
			return install(rest);
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
			return 2;
	}
}

const yesNo = (q: string) => prompt(`${q} [y/N]`)?.trim().toLowerCase() === "y";

function choose<T>(title: string, items: T[], label: (t: T) => string): T {
	if (items.length === 1) return items[0]!;
	info(title);
	items.forEach((it, i) => info(`  ${i + 1}) ${label(it)}`));
	const n = Number(prompt("Choose a number:")?.trim());
	const picked = items[n - 1];
	if (!picked) throw new ClaimError("No valid choice. Nothing was changed.");
	return picked;
}

async function install(args: string[]): Promise<number> {
	const { values } = parseArgs({
		args,
		options: {
			profile: { type: "string" },
			account: { type: "string" },
			apps: { type: "string" },
			domain: { type: "string" },
			"no-domain": { type: "boolean" },
			"dry-run": { type: "boolean" },
			yes: { type: "boolean", short: "y" },
		},
	});
	const dryRun = !!values["dry-run"];

	// 1. profile + account
	let profile = values.profile;
	if (!profile) {
		const list = await cfRun({}, ["auth", "list"]);
		const names = list.code === 0 ? (JSON.parse(list.stdout || "[]") as { name: string }[]).map((p) => p.name) : [];
		profile = names.length ? choose("cf profiles:", names, (n) => n) : undefined;
	}
	const base: CfContext = { profile };
	const me = await whoami(base);
	if (!me.authenticated) {
		throw new ClaimError(`Not signed in to Cloudflare${profile ? ` (profile ${profile})` : ""}. Run: cf auth login${profile ? ` --profile ${profile}` : ""}`);
	}
	const account = values.account
		? me.accounts.find((a) => a.id === values.account)
		: choose("Cloudflare accounts:", me.accounts, (a) => `${a.name} (${a.id})`);
	if (!account) throw new ClaimError(`Account ${values.account} is not available to this profile`);
	const ctx: CfContext = { profile, accountId: account.id };
	info(`✓ account: ${account.name}${profile ? ` (profile ${profile})` : ""}`);

	// 2. apps
	const apps = (values.apps ?? prompt("Apps to install:", "tumbler") ?? "").split(",").map((a) => a.trim()).filter(Boolean);
	for (const a of apps) {
		if (a === "nodewarden") throw new ClaimError("NodeWarden is not automated yet: deploy it with its own Wrangler config, then run ./install.sh nodewarden-claim right away.");
		if (a !== "tumbler") throw new ClaimError(`Unknown app: ${a}`);
	}
	if (!apps.includes("tumbler")) throw new ClaimError("Nothing to install.");

	// 3. domain
	const domainInput = values["no-domain"] ? "" : (values.domain ?? prompt("Custom domain for Tumbler (blank = workers.dev), e.g. tumbler.example.com:", "")?.trim() ?? "");
	const domain = domainInput ? normalizeDomain(domainInput) : undefined;

	info(`\nPlan: ${dryRun ? "DRY RUN, nothing is created or uploaded. " : ""}Install/upgrade Tumbler on "${account.name}"` +
		`${domain ? ` at https://${domain}` : " on workers.dev"}.`);
	if (!dryRun && !values.yes && !yesNo("Proceed?")) {
		info("Aborted. Nothing was changed.");
		return 1;
	}

	const result = await installTumbler({ ctx, domain, dryRun, yes: !!values.yes, confirm: yesNo, log: info });
	if (dryRun || !result.url) return 0;

	// 4. first admin
	const res = await fetch(`${result.url}/api/setup`);
	const setup = (await res.json().catch(() => ({}))) as { needed?: boolean };
	if (!setup.needed) {
		info(`\n✓ Tumbler is up to date at ${result.url}. Accounts already exist; invite users from Settings → Sync.`);
		return 0;
	}
	info("\nCreate the first admin account.");
	const username = normalizeTumblerUsername(prompt("Admin username:", "admin")?.trim() ?? "");
	const password = await readNewPassword(username);
	info("Deriving keys and creating the admin account…");
	printTumblerSummary(await setupTumblerAdmin({ url: result.url, setupToken: result.setupToken!, username, password }));
	return 0;
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
	if (e instanceof ClaimError || e instanceof CancelledError || e instanceof CfError) {
		console.error(`\n✖ ${e.message}`);
		process.exit(1);
	}
	throw e;
}
