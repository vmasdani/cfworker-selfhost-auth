// Installer entry point. Apps it can install: ./apps.ts
//
// Commands:
//   install (default)  Install or upgrade apps on a Cloudflare account (./install-local.ts).
//       [--profile <cf profile>] [--account <id>] [--apps tumbler,coffer,nodewarden] [--domain <host> | --no-domain]
//       [--variant kv|r2] [--dry-run] [--yes]
//     Idempotent; re-running upgrades in place. Never deletes resources.
//   nodewarden-claim --url <worker url> [--username <name or email>] [--name <display name>] [--yes]
//   setup-admin --app tumbler|coffer --url <worker url> [--username <name>] [--yes]
//     Setup token from <APP>_SETUP_TOKEN (e.g. COFFER_SETUP_TOKEN), or prompted (hidden).
//     `tumbler-setup-admin` is kept as an alias for `setup-admin --app tumbler`.
// Missing values are prompted for interactively. Passwords are always typed by the user
// (hidden, twice); on non-TTY stdin they are read as lines, e.g. for CI.
//
// NodeWarden (./install-nodewarden.ts) deploys from its pinned upstream commit with Wrangler, and its
// admin is claimed in the same run, right after deploy.

import { parseArgs } from "node:util";
import { APPS } from "./apps.ts";
import { installNodewarden, type NodewardenVariant } from "./install-nodewarden.ts";
import { installLocal, LOCAL_APPS, normalizeDomain, type LocalApp } from "./install-local.ts";
import { CfError, cfRun, whoami, type CfContext } from "./lib/cf.ts";
import { MIN_MASTER_PASSWORD_LENGTH, validateMasterPassword } from "./lib/password.ts";
import { CancelledError, readHidden } from "./lib/tty.ts";
import { assertClaimable, ClaimError, claimFirstAdmin, loginFromUsername, printClaimSummary } from "./nodewarden.ts";
import { assertSetupNeeded, normalizeUsername, printAdminSummary, setupAdmin } from "./local-admin.ts";

const info = (msg: string) => process.stderr.write(`${msg}\n`);

const USAGE = `Usage:
  ./install.sh [install] [--profile <cf profile>] [--account <id>] [--apps tumbler,coffer,nodewarden]
               [--domain <host> | --no-domain] [--variant kv|r2] [--dry-run] [--yes]
  ./install.sh nodewarden-claim [--url <worker url>] [--username <name or email>] [--name <display name>] [--yes]
  ./install.sh setup-admin --app tumbler|coffer [--url <worker url>] [--username <name>] [--yes]

Apps: ${APPS.map((a) => a.id).join(", ")}. --domain applies when installing one app; otherwise you are asked per app.`;

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
		case "setup-admin":
		case "tumbler-setup-admin": {
			const { values } = parseArgs({
				args: rest,
				options: { app: { type: "string" }, url: { type: "string" }, username: { type: "string" }, yes: { type: "boolean", short: "y" } },
			});
			const id = command === "tumbler-setup-admin" ? "tumbler" : (values.app ?? prompt("App (tumbler, coffer):", "coffer")?.trim() ?? "");
			const app = LOCAL_APPS[id as LocalApp["id"]];
			if (!app) throw new ClaimError(`--app must be one of: ${Object.keys(LOCAL_APPS).join(", ")}`);
			const url = values.url ?? prompt(`${app.name} URL:`)?.trim();
			if (!url) {
				console.error(USAGE);
				return 2;
			}
			await assertSetupNeeded(app, url);
			const setupToken = process.env[`${app.envPrefix}_SETUP_TOKEN`] || (await readHidden("ADMIN_SETUP_TOKEN:"));
			const username = normalizeUsername(values.username ?? prompt("Admin username:", "admin")?.trim() ?? "");
			const password = await readNewPassword(username);
			if (!values.yes && prompt(`Create ${app.name} admin "${username}" now? [y/N]`)?.trim().toLowerCase() !== "y") {
				info("Aborted. Nothing was created.");
				return 1;
			}
			info("Deriving keys and creating the admin account…");
			printAdminSummary(app, await setupAdmin(app, { url, setupToken, username, password }));
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
			variant: { type: "string" },
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
	const apps = (values.apps ?? prompt("Apps to install (tumbler, coffer, nodewarden):", "tumbler") ?? "")
		.split(",").map((a) => a.trim().toLowerCase()).filter(Boolean);
	for (const a of apps) if (!APPS.some((x) => x.id === a)) throw new ClaimError(`Unknown app: ${a}`);
	if (!apps.length) throw new ClaimError("Nothing to install.");
	const variant = (values.variant ?? "kv") as NodewardenVariant;
	if (variant !== "kv" && variant !== "r2") throw new ClaimError("--variant must be kv or r2");

	// 3. domains (--domain applies when installing a single app)
	const domains: Record<string, string | undefined> = {};
	for (const a of apps) {
		const name = appName(a);
		const input = values["no-domain"]
			? ""
			: ((apps.length === 1 ? values.domain : undefined) ??
				prompt(`Custom domain for ${name} (blank = workers.dev), e.g. ${a}.example.com:`, "")?.trim() ?? "");
		domains[a] = input ? normalizeDomain(input) : undefined;
	}

	info(`\nPlan: ${dryRun ? "DRY RUN, nothing is created or uploaded. " : ""}On "${account.name}":`);
	for (const a of apps) {
		info(`  • ${a === "nodewarden" ? `NodeWarden (${variant.toUpperCase()} attachments)` : appName(a)} ${domains[a] ? `at https://${domains[a]}` : "on workers.dev"}`);
	}
	if (apps.includes("nodewarden") && !dryRun) {
		info("  NodeWarden makes the first registered account the admin, so its admin is claimed right after deploy.");
	}
	if (!dryRun && !values.yes && !yesNo("Proceed?")) {
		info("Aborted. Nothing was changed.");
		return 1;
	}

	for (const a of apps) {
		info(`\n— ${appName(a)} —`);
		if (a === "nodewarden") await installNodewardenApp(ctx, domains[a], variant, dryRun, !!values.yes);
		else await installLocalApp(LOCAL_APPS[a as LocalApp["id"]], ctx, domains[a], dryRun, !!values.yes);
	}
	return 0;
}

const appName = (id: string) => (id === "nodewarden" ? "NodeWarden" : (LOCAL_APPS[id as LocalApp["id"]]?.name ?? id));

async function installLocalApp(app: LocalApp, ctx: CfContext, domain: string | undefined, dryRun: boolean, yes: boolean): Promise<void> {
	const result = await installLocal(app, { ctx, domain, dryRun, yes, confirm: yesNo, log: info });
	if (dryRun || !result.url) return;
	const res = await fetch(`${result.url}/api/setup`);
	const setup = (await res.json().catch(() => ({}))) as { needed?: boolean };
	if (!setup.needed) {
		info(`✓ ${app.name} is up to date at ${result.url}. Accounts already exist; invite users from ${app.inviteHint}.`);
		return;
	}
	info(`\nCreate the first ${app.name} admin account.`);
	const username = normalizeUsername(prompt("Admin username:", "admin")?.trim() ?? "");
	const password = await readNewPassword(username);
	info("Deriving keys and creating the admin account…");
	printAdminSummary(app, await setupAdmin(app, { url: result.url, setupToken: result.setupToken!, username, password }));
}

async function installNodewardenApp(ctx: CfContext, domain: string | undefined, variant: NodewardenVariant, dryRun: boolean, yes: boolean): Promise<void> {
	const result = await installNodewarden({ ctx, domain, variant, dryRun, yes, confirm: yesNo, log: info });
	if (dryRun || !result.url) return;
	try {
		await assertClaimable(result.url);
	} catch (e) {
		if (e instanceof ClaimError && /already has an account/.test(e.message)) {
			info(`✓ NodeWarden is up to date at ${result.url}. Its admin account already exists.`);
			info("  If you did not create that account yourself, do not use this instance: wipe nodewarden-db and its KV namespace, then redeploy.");
			return;
		}
		throw e;
	}
	info("\nClaim the NodeWarden admin account now.");
	const username = prompt("Admin login: a username (e.g. admin) or your own email (e.g. you@proton.me):", "admin")?.trim() ?? "";
	const email = loginFromUsername(username, result.url);
	const name = prompt("Display name:", username.split("@")[0])?.trim();
	info(`Admin login will be: ${email} (Bitwarden clients sign in with an email-shaped login; no mail is sent to it).`);
	const password = await readNewPassword(email);
	info("Deriving keys and registering the admin account…");
	printClaimSummary(await claimFirstAdmin({ url: result.url, email, password, name: name || undefined }));
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
