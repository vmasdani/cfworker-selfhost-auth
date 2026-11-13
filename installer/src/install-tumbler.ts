// Install or upgrade Tumbler on a Cloudflare account. Idempotent: re-running upgrades in place.
//
//   1. account (cf profile + account id)
//   2. optional custom domain: zone must be in the account; no conflicting DNS record
//   3. D1 `tumbler-db`: reuse by name, or create (asks first)
//   4. apply D1 migrations
//   5. secrets: SERVER_SECRET only if missing (never rotated: every login verifier depends on it);
//      ADMIN_SETUP_TOKEN fresh on every run (it only works while the server has no users, so rotating is
//      harmless and the installer always holds a valid one). Values go through a 0600 temp file to
//      `cf deploy --secrets-file`, then the file is deleted. cf keeps secrets not in the file.
//   6. deploy, wait for /api/health
//   7. first admin, if the server has no users
// Nothing is ever deleted.

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	cfRun,
	CfError,
	createD1,
	dnsRecordsNamed,
	isWorkerManaged,
	findD1,
	workerSecretNames,
	zoneFor,
	type CfContext,
} from "./lib/cf.ts";
import { generateSecret } from "./lib/password.ts";
import { ClaimError } from "./nodewarden.ts";
import { waitHealthy } from "./lib/wait.ts";

const APP_DIR = join(import.meta.dir, "..", "..", "apps", "tumbler");
const WORKER = "tumbler";
const DB_NAME = "tumbler-db";

export interface TumblerInstallOptions {
	ctx: CfContext;
	domain?: string;
	dryRun: boolean;
	yes: boolean;
	confirm: (question: string) => boolean;
	log: (msg: string) => void;
}

export interface TumblerInstallResult {
	url: string | null;
	setupToken: string | null;
	firstInstall: boolean;
}

const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function normalizeDomain(input: string): string {
	const d = input.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
	if (!HOST.test(d)) throw new ClaimError(`Not a valid hostname: ${input}`);
	return d;
}

export async function installTumbler(o: TumblerInstallOptions): Promise<TumblerInstallResult> {
	const { ctx, log } = o;
	const env: Record<string, string> = {};

	const existingSecrets = await workerSecretNames(ctx, WORKER);
	const firstInstall = existingSecrets === null;

	// 2. domain
	if (o.domain) {
		const zone = await zoneFor(ctx, o.domain);
		if (!zone) throw new ClaimError(`No zone for ${o.domain} in this account. Add the domain to Cloudflare first, or install without a custom domain.`);
		if (zone.status !== "active") throw new ClaimError(`Zone ${zone.name} is ${zone.status}, not active`);
		const records = await dnsRecordsNamed(ctx, zone.name, o.domain);
		const foreign = records.filter((r) => !isWorkerManaged(r));
		if (foreign.length) {
			throw new ClaimError(`${o.domain} already has DNS records (${foreign.map((r) => r.type).join(", ")}). Pick another hostname or remove them yourself.`);
		}
		// A Worker-managed record is ours on upgrade; on a first install it belongs to some other Worker.
		if (records.length && firstInstall) {
			throw new ClaimError(`${o.domain} is already the custom domain of another Worker. Pick another hostname.`);
		}
		log(`✓ domain ${o.domain} (zone ${zone.name})`);
		env.TUMBLER_DOMAIN = o.domain;
	} else {
		log("• no custom domain: serving on workers.dev");
	}

	// 3. database
	let db = await findD1(ctx, DB_NAME);
	if (db) log(`✓ D1 ${DB_NAME} exists (${db.uuid}), reusing it`);
	else if (o.dryRun) log(`• would create D1 ${DB_NAME}`);
	else {
		if (!o.yes && !o.confirm(`Create D1 database "${DB_NAME}"?`)) throw new ClaimError("Aborted. Nothing was created.");
		db = await createD1(ctx, DB_NAME);
		log(`✓ created D1 ${DB_NAME} (${db.uuid})`);
	}
	if (db) env.TUMBLER_D1_ID = db.uuid;

	// 4. migrations
	if (db && !o.dryRun) {
		const r = await cfRun(ctx, ["d1", "migrations", "apply", db.uuid, "--dir", join(APP_DIR, "migrations")], { cwd: APP_DIR });
		if (r.code !== 0) throw new CfError(["d1", "migrations", "apply"], r.code, r.stderr);
		log("✓ migrations applied");
	} else log("• would apply migrations");

	// 5. secrets
	const secrets: Record<string, string> = {};
	if (!existingSecrets?.includes("SERVER_SECRET")) secrets.SERVER_SECRET = generateSecret(32);
	secrets.ADMIN_SETUP_TOKEN = generateSecret(32);
	log(`✓ secrets to set: ${Object.keys(secrets).join(", ")} (values never printed)${secrets.SERVER_SECRET ? "" : "; existing SERVER_SECRET kept"}`);

	// 6. deploy
	const dir = mkdtempSync(join(tmpdir(), "cfsa-"));
	const file = join(dir, "secrets.json");
	try {
		writeFileSync(file, JSON.stringify(secrets), { mode: 0o600 });
		chmodSync(file, 0o600);
		const args = ["deploy", ...(o.dryRun ? ["--dry-run"] : []), "--secrets-file", file];
		log(o.dryRun ? "• building (dry run, nothing uploaded)…" : "• deploying…");
		const r = await cfRun(ctx, args, { cwd: APP_DIR, env });
		if (r.code !== 0) throw new CfError(["deploy"], r.code, r.stderr + r.stdout);
		if (o.dryRun) {
			log("✓ dry run OK");
			return { url: null, setupToken: null, firstInstall };
		}
		const url = o.domain ? `https://${o.domain}` : findWorkersDevUrl(r.stdout + r.stderr);
		if (!url) throw new ClaimError("Deployed, but could not find the Worker URL in cf output. Pass --domain or check the dashboard.");
		log(`✓ deployed: ${url}`);
		await waitHealthy(url, "/api/health", log);
		return { url, setupToken: secrets.ADMIN_SETUP_TOKEN, firstInstall };
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

function findWorkersDevUrl(out: string): string | null {
	return /https:\/\/[a-z0-9.-]+\.workers\.dev/i.exec(out)?.[0] ?? null;
}
