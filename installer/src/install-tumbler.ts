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
	findD1,
	workerSecretNames,
	zoneFor,
	type CfContext,
} from "./lib/cf.ts";
import { generateSecret } from "./lib/password.ts";
import { ClaimError } from "./nodewarden.ts";

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

	// 2. domain
	if (o.domain) {
		const zone = await zoneFor(ctx, o.domain);
		if (!zone) throw new ClaimError(`No zone for ${o.domain} in this account. Add the domain to Cloudflare first, or install without a custom domain.`);
		if (zone.status !== "active") throw new ClaimError(`Zone ${zone.name} is ${zone.status}, not active`);
		const existing = await dnsRecordsNamed(ctx, zone.name, o.domain);
		// A Worker custom domain shows up as a read-only record; anything else is a conflict.
		const conflict = existing.filter((r) => !/worker/i.test(`${r.type} ${r.content ?? ""}`));
		if (conflict.length) {
			throw new ClaimError(`${o.domain} already has DNS records (${conflict.map((r) => r.type).join(", ")}). Pick another hostname or remove them yourself.`);
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
	const existing = await workerSecretNames(ctx, WORKER);
	const firstInstall = existing === null;
	const secrets: Record<string, string> = {};
	if (!existing?.includes("SERVER_SECRET")) secrets.SERVER_SECRET = generateSecret(32);
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
		await waitHealthy(url, log);
		return { url, setupToken: secrets.ADMIN_SETUP_TOKEN, firstInstall };
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}

function findWorkersDevUrl(out: string): string | null {
	return /https:\/\/[a-z0-9.-]+\.workers\.dev/i.exec(out)?.[0] ?? null;
}

/** New custom domains need DNS + a certificate; that can take a few minutes. */
async function waitHealthy(url: string, log: (m: string) => void): Promise<void> {
	const deadline = Date.now() + 10 * 60_000;
	let announced = false;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(10_000) });
			if (res.ok) {
				log("✓ server is up");
				return;
			}
		} catch {
			// DNS or TLS not ready yet
		}
		if (!announced) {
			log("• waiting for the domain and certificate (can take a few minutes)…");
			announced = true;
		}
		await Bun.sleep(5000);
	}
	throw new ClaimError(`${url} did not come up within 10 minutes. Re-run the installer later; it is safe to repeat.`);
}
