#!/usr/bin/env bun
// Parity check between the TypeScript standalone server (Bun) and the Rust one, for one app:
//
//   1. Start both on fresh data directories with the same SERVER_SECRET and ADMIN_SETUP_TOKEN.
//   2. Run the same request scenario against each (real client crypto from packages/crypto and
//      packages/totp) and diff status, headers and JSON, with random values masked.
//   3. Compare what each wrote to its database (verifiers, wrapped keys, entries...).
//   4. Swap: each server opens a copy of the other's database. Sessions, passwords, recovery keys and
//      sealed login-TOTP secrets created by one implementation must work on the other.
//
//   cargo build --release -p tumbler-rs --bin tumbler-server && bun run build:standalone
//   bun scripts/rust-parity.ts tumbler        (or: coffer)
//
// Exits non-zero on any difference. Uses throwaway secrets; never point it at real data.

import { Database } from "bun:sqlite";
import { cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
	deriveKeys,
	generateVaultKey,
	hkdf,
	makeAccountMaterial,
	makePasswordMaterial,
	parseRecoveryKey,
	recoverySubkeys,
	toB64,
	utf8,
	type AccountMaterial,
} from "../packages/crypto/src/index.ts";
import { base32Decode, hotp, importOtpKey, totpCounter } from "../packages/totp/src/index.ts";

const APP = process.argv[2] ?? "tumbler";
const ROOT = resolve(import.meta.dir, "..");
const SECRET = "parity-only-server-secret-0123456789abcdef";
const SETUP = "parity-only-setup-token-0123456789abcdef0123";
const PORTS = { ts: 18701, rs: 18702 } as const;
type Impl = keyof typeof PORTS;

// --- servers ------------------------------------------------------------------------------------------

interface Server {
	impl: Impl;
	base: string;
	proc: ReturnType<typeof Bun.spawn>;
	dataDir: string;
	log: string[];
}

const running = new Set<ReturnType<typeof Bun.spawn>>();
process.on("exit", () => running.forEach((p) => p.kill("SIGKILL")));

async function start(impl: Impl, dataDir: string): Promise<Server> {
	const port = PORTS[impl];
	// Bun listens with SO_REUSEPORT, so a leftover server would silently share the port.
	if (await fetch(`http://127.0.0.1:${port}/api/health`).then(() => true, () => false)) throw new Error(`port ${port} is already in use`);
	const env = {
		...process.env,
		HOST: "127.0.0.1",
		PORT: String(port),
		DATA_DIR: dataDir,
		SERVER_SECRET: SECRET,
		ADMIN_SETUP_TOKEN: SETUP,
		PUBLIC_URL: `http://localhost:${port}`,
		STATIC_DIR: join(ROOT, "apps", APP, "dist"),
		NODE_ENV: "production",
	};
	mkdirSync(dataDir, { recursive: true });
	const cmd = impl === "ts" ? [process.execPath, "run", join(ROOT, "apps", APP, "server.ts")] : [join(ROOT, "target", "release", `${APP}-server`)];
	const proc = Bun.spawn(cmd, { env, cwd: dataDir, stdout: "pipe", stderr: "pipe" });
	running.add(proc);
	const s: Server = { impl, base: `http://127.0.0.1:${port}`, proc, dataDir, log: [] };
	for (const stream of [proc.stdout, proc.stderr] as ReadableStream<Uint8Array>[]) {
		void (async () => {
			for await (const chunk of stream) s.log.push(new TextDecoder().decode(chunk));
		})();
	}
	for (let i = 0; i < 100; i++) {
		try {
			if ((await fetch(`${s.base}/api/health`)).ok) return s;
		} catch {
			// not up yet
		}
		await Bun.sleep(100);
	}
	throw new Error(`${impl} did not start:\n${s.log.join("")}`);
}

async function stop(s: Server) {
	s.proc.kill("SIGTERM");
	await s.proc.exited;
	running.delete(s.proc);
}

// --- requests -----------------------------------------------------------------------------------------

type Jar = Map<string, string>;
const COOKIE = APP === "coffer" ? "__Host-coffer_session" : "__Host-tumbler_session";

interface Out {
	step: string;
	status: number;
	headers: Record<string, string>;
	body: unknown;
}

const SKIP_HEADERS = new Set(["date", "connection", "keep-alive", "transfer-encoding", "server"]);

async function call(
	s: Server,
	step: string,
	method: string,
	path: string,
	o: { body?: unknown; jar?: Jar; headers?: Record<string, string>; raw?: string } = {},
): Promise<Out & { json: any }> {
	const headers: Record<string, string> = { ...o.headers };
	if (o.body !== undefined && !("content-type" in headers)) headers["content-type"] = "application/json";
	const cookie = o.jar?.get(COOKIE);
	if (cookie) headers.cookie = `${COOKIE}=${cookie}`;
	const res = await fetch(s.base + path, {
		method,
		headers,
		body: o.raw ?? (o.body === undefined ? undefined : JSON.stringify(o.body)),
		redirect: "manual",
		decompress: false,
	} as RequestInit);
	const h: Record<string, string> = {};
	res.headers.forEach((v, k) => {
		if (!SKIP_HEADERS.has(k)) h[k] = v;
	});
	const setCookie = res.headers.get("set-cookie");
	if (setCookie && o.jar) {
		const m = new RegExp(`^${COOKIE}=([^;]*)`).exec(setCookie);
		if (m) m[1] ? o.jar.set(COOKIE, m[1]) : o.jar.delete(COOKIE);
	}
	const buf = new Uint8Array(await res.arrayBuffer());
	const text = new TextDecoder().decode(buf);
	let json: any = null;
	let body: unknown;
	if ((res.headers.get("content-type") ?? "").includes("json") && text) {
		json = JSON.parse(text);
		body = json;
	} else if (res.headers.get("content-encoding")) {
		body = `<${res.headers.get("content-encoding")} ${buf.length > 0 ? "body" : "empty"}>`;
		delete h["content-length"];
	} else {
		body = text.length > 200 ? `<${buf.length} bytes sha256:${new Bun.CryptoHasher("sha256").update(buf).digest("hex").slice(0, 16)}>` : text;
	}
	return { step, status: res.status, headers: h, body, json };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RANDOM_KEYS = new Set(["token", "secret", "uri", "retryAfter", "lastUsedAt"]);

/** Mask values that legitimately differ between runs: UUIDs, timestamps, random tokens. */
function mask(v: unknown, key = ""): unknown {
	if (RANDOM_KEYS.has(key) && v !== null) return `<${key}>`;
	if (typeof v === "string") return UUID.test(v) ? "<uuid>" : v;
	if (typeof v === "number") return v > 1e12 ? "<ts>" : v;
	if (Array.isArray(v)) return v.map((x) => mask(x));
	if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mask(x, k)]));
	return v;
}

function maskOut(o: Out): Out {
	const headers = { ...o.headers };
	if (headers["set-cookie"]) headers["set-cookie"] = headers["set-cookie"].replace(/=[A-Za-z0-9_-]{43};/, "=<token>;");
	if (headers["retry-after"]) headers["retry-after"] = "<n>";
	return { step: o.step, status: o.status, headers, body: mask(o.body) };
}

// --- client material (shared by both runs, so stored verifiers must match) ------------------------------

interface Person {
	username: string;
	password: string;
	material: AccountMaterial;
	recoveryKey: string;
}

async function person(username: string, password: string): Promise<Person> {
	const { material, recoveryKey } = await makeAccountMaterial(password, generateVaultKey(), 100_000);
	return { username, password, material, recoveryKey };
}

async function authKey(p: { password: string }, kdf: any): Promise<string> {
	return toB64((await deriveKeys(p.password, kdf)).authKey);
}

async function totpCode(secret: string, stepOffset = 0): Promise<string> {
	return hotp(await importOtpKey(base32Decode(secret)), totpCounter(Date.now()) + stepOffset);
}

// --- scenarios ----------------------------------------------------------------------------------------

interface Ctx {
	admin: Person;
	bob: Person;
	newPassword: Awaited<ReturnType<typeof makePasswordMaterial>>;
	recoveryPassword: Awaited<ReturnType<typeof makePasswordMaterial>>;
	vaultKey: Uint8Array;
}

/** Cookies and secrets a run leaves behind for the cross-database phase. */
interface State {
	adminJar: Jar;
	bobJar: Jar;
	bobTotpSecret: string;
	/** Last login-TOTP step bob used; a new login needs a later step. */
	bobLastStep: number;
	extra: Record<string, string>;
}

async function accountsScenario(s: Server, c: Ctx, out: Out[]): Promise<State> {
	const r = async (...a: Parameters<typeof call>) => {
		const x = await call(...a);
		out.push(x);
		return x;
	};
	const adminJar: Jar = new Map();
	const bobJar: Jar = new Map();
	const a = c.admin;

	await r(s, "health", "GET", "/api/health");
	await r(s, "health HEAD", "HEAD", "/api/health");
	await r(s, "setup status", "GET", "/api/setup");
	await r(s, "unknown route", "GET", "/api/nope");
	await r(s, "trailing slash", "GET", "/api/health/");
	await r(s, "csrf origin", "POST", "/api/prelogin", { body: { username: "x" }, headers: { origin: "https://evil.example" } });
	await r(s, "json required", "POST", "/api/prelogin", { raw: "{}", headers: { "content-type": "text/plain" } });
	await r(s, "invalid json", "POST", "/api/prelogin", { raw: "[1]" });
	await r(s, "bad username", "POST", "/api/prelogin", { body: { username: "A" } });
	await r(s, "decoy prelogin", "POST", "/api/prelogin", { body: { username: "nobody" } });
	await r(s, "setup bad token", "POST", "/api/setup", { body: { setupToken: "nope" }, headers: { "x-forwarded-for": "10.9.0.1" } });
	await r(s, "setup bad material", "POST", "/api/setup", { body: { setupToken: SETUP, username: a.username, kdf: { alg: "x" } } });
	await r(s, "setup", "POST", "/api/setup", { body: { setupToken: SETUP, username: a.username, ...a.material }, jar: adminJar });
	await r(s, "setup again", "POST", "/api/setup", { body: { setupToken: SETUP, username: "other", ...a.material } });
	await r(s, "session", "GET", "/api/session", { jar: adminJar });
	await r(s, "session none", "GET", "/api/session");
	await r(s, "session bad cookie", "GET", "/api/session", { headers: { cookie: `${COOKIE}=${"A".repeat(43)}` } });
	const pre = await r(s, "prelogin", "POST", "/api/prelogin", { body: { username: a.username.toUpperCase() } });
	await r(s, "login wrong", "POST", "/api/login", { body: { username: a.username, authKey: toB64(new Uint8Array(32)) } });
	await r(s, "login short key", "POST", "/api/login", { body: { username: a.username, authKey: "AAAA" } });
	await r(s, "login", "POST", "/api/login", { body: { username: a.username, authKey: await authKey(a, pre.json.kdf) }, jar: adminJar });

	// Rate limit on its own client IP (X-Forwarded-For is trusted on loopback).
	for (let i = 0; i < 10; i++) {
		await call(s, "", "POST", "/api/login", { body: { username: "limited", authKey: toB64(new Uint8Array(32)) }, headers: { "x-forwarded-for": "10.0.0.7" } });
	}
	await r(s, "rate limited", "POST", "/api/login", { body: { username: "limited", authKey: toB64(new Uint8Array(32)) }, headers: { "x-forwarded-for": "10.0.0.7" } });

	// Invites and registration.
	await r(s, "admin unauth", "GET", "/api/admin/users");
	await r(s, "admin unknown", "GET", "/api/admin/nope", { jar: adminJar });
	await r(s, "invite bad role", "POST", "/api/admin/invites", { body: { role: "root" }, jar: adminJar });
	const inv = await r(s, "invite", "POST", "/api/admin/invites", { body: { ttlHours: 2 }, jar: adminJar });
	await r(s, "invite check", "GET", `/api/invites/check?token=${encodeURIComponent(inv.json.token)}`);
	await r(s, "invite check bad", "GET", "/api/invites/check?token=nope");
	const b = c.bob;
	await r(s, "register taken", "POST", "/api/register", { body: { invite: inv.json.token, username: a.username, ...b.material } });
	await r(s, "register", "POST", "/api/register", { body: { invite: inv.json.token, username: b.username, ...b.material }, jar: bobJar });
	await r(s, "register reuse", "POST", "/api/register", { body: { invite: inv.json.token, username: "carol", ...b.material } });
	await r(s, "admin users", "GET", "/api/admin/users", { jar: adminJar });
	await r(s, "admin invites", "GET", "/api/admin/invites", { jar: adminJar });
	await r(s, "not admin", "GET", "/api/admin/users", { jar: bobJar });
	const inv2 = await r(s, "invite 2", "POST", "/api/admin/invites", { body: { role: "admin" }, jar: adminJar });
	await r(s, "invite delete", "DELETE", `/api/admin/invites/${inv2.json.id}`, { jar: adminJar });

	// Login TOTP for bob: setup, enable, replay rejected, next step accepted.
	const setup = await r(s, "totp setup", "POST", "/api/account/totp/setup", { body: {}, jar: bobJar });
	const bobTotpSecret: string = setup.json.secret;
	await r(s, "totp enable wrong", "POST", "/api/account/totp/enable", { body: { code: "000000" }, jar: bobJar });
	const code = await totpCode(bobTotpSecret);
	await r(s, "totp enable", "POST", "/api/account/totp/enable", { body: { code: ` ${code} ` }, jar: bobJar });
	await r(s, "totp setup again", "POST", "/api/account/totp/setup", { body: {}, jar: bobJar });
	const bobKey = await authKey(b, b.material.kdf);
	await r(s, "login totp required", "POST", "/api/login", { body: { username: b.username, authKey: bobKey } });
	await r(s, "login totp replay", "POST", "/api/login", { body: { username: b.username, authKey: bobKey, totp: code } });
	const bobLastStep = totpCounter(Date.now()) + 1;
	await r(s, "login totp", "POST", "/api/login", { body: { username: b.username, authKey: bobKey, totp: await totpCode(bobTotpSecret, 1) }, jar: bobJar });

	// Password change (admin) and recovery (admin, which also clears its sessions).
	await r(s, "password wrong", "POST", "/api/account/password", { body: { currentAuthKey: toB64(new Uint8Array(32)), ...c.newPassword }, jar: adminJar });
	const curKey = await authKey(a, a.material.kdf);
	await r(s, "password", "POST", "/api/account/password", { body: { currentAuthKey: curKey, ...c.newPassword }, jar: adminJar });
	const rk = toB64((await recoverySubkeys(parseRecoveryKey(a.recoveryKey))).authKey);
	await r(s, "recover wrong", "POST", "/api/recover/start", { body: { username: a.username, recoveryAuthKey: toB64(new Uint8Array(32)) } });
	await r(s, "recover start", "POST", "/api/recover/start", { body: { username: a.username, recoveryAuthKey: rk } });
	const recJar: Jar = new Map();
	await r(s, "recover finish", "POST", "/api/recover/finish", { body: { username: a.username, recoveryAuthKey: rk, ...c.recoveryPassword }, jar: recJar });
	await r(s, "old session gone", "GET", "/api/session", { jar: adminJar });
	adminJar.clear();
	const pre2 = await r(s, "prelogin after recovery", "POST", "/api/prelogin", { body: { username: a.username } });
	await r(s, "login after recovery", "POST", "/api/login", { body: { username: a.username, authKey: await authKey({ password: "recovered pw" }, pre2.json.kdf) }, jar: adminJar });
	await r(s, "logout", "POST", "/api/logout", { body: {}, jar: recJar });
	await r(s, "after logout", "GET", "/api/session", { jar: recJar });

	return { adminJar, bobJar, bobTotpSecret, bobLastStep, extra: {} };
}

async function tumblerScenario(s: Server, c: Ctx, out: Out[]): Promise<State> {
	const st = await accountsScenario(s, c, out);
	const r = async (...a: Parameters<typeof call>) => {
		const x = await call(...a);
		out.push(x);
		return x;
	};
	const jar = st.adminJar;
	const iv = toB64(new Uint8Array(12).fill(1));
	const t0 = 1_700_000_000_000;
	await r(s, "sync unauth", "GET", "/api/sync");
	await r(s, "sync empty", "GET", "/api/sync", { jar });
	await r(s, "sync bad cursor", "GET", "/api/sync?since=-1", { jar });
	await r(s, "sync push not array", "POST", "/api/sync", { body: { changes: {} }, jar });
	await r(s, "sync push bad id", "POST", "/api/sync", { body: { changes: [{ id: "a b", deleted: false }] }, jar });
	await r(s, "sync push bad iv", "POST", "/api/sync", { body: { changes: [{ id: "e1", deleted: false, iv: "AAAA", ct: "AAAA", revision: 1, updatedAt: t0 }] }, jar });
	await r(s, "sync push future", "POST", "/api/sync", { body: { changes: [{ id: "e1", deleted: false, iv, ct: "AAAA", revision: 1, updatedAt: Date.now() + 3 * 86_400_000 }] }, jar });
	await r(s, "sync push empty", "POST", "/api/sync", { body: { changes: [] }, jar });
	await r(s, "sync push", "POST", "/api/sync", {
		body: {
			changes: [
				{ id: "e1", deleted: false, iv, ct: toB64(new Uint8Array(40).fill(2)), revision: 1, updatedAt: t0 },
				{ id: "e2", deleted: false, iv, ct: toB64(new Uint8Array(40).fill(3)), revision: 1, updatedAt: t0 },
				{ id: "e3", deleted: true, revision: 2, updatedAt: t0 },
			],
		},
		jar,
	});
	await r(s, "sync conflict", "POST", "/api/sync", {
		body: {
			changes: [
				{ id: "e1", deleted: false, iv, ct: "AAAA", revision: 1, updatedAt: t0 - 1 },
				{ id: "e2", deleted: false, iv, ct: "BBBB", revision: 2, updatedAt: t0 },
				{ id: "e1", deleted: true, revision: 1, updatedAt: t0 },
			],
		},
		jar,
	});
	await r(s, "sync pull", "GET", "/api/sync?since=0", { jar });
	await r(s, "sync pull cursor", "GET", "/api/sync?since=2", { jar });
	return st;
}

/** Static files: same bytes, headers and SPA fallback. */
async function staticScenario(s: Server, out: Out[]) {
	const r = async (...a: Parameters<typeof call>) => out.push(await call(...a));
	const index = await call(s, "", "GET", "/");
	await r(s, "static index", "GET", "/");
	await r(s, "static spa route", "GET", "/settings/x");
	await r(s, "static index br", "GET", "/", { headers: { "accept-encoding": "gzip, br" } });
	await r(s, "static gzip", "GET", "/", { headers: { "accept-encoding": "gzip" } });
	await r(s, "static 304", "GET", "/", { headers: { "if-none-match": index.headers.etag ?? "" } });
	await r(s, "static missing file", "GET", "/missing.png");
	await r(s, "static post", "POST", "/", { raw: "x" });
	await r(s, "static head", "HEAD", "/icon.svg");
	await r(s, "static headers file", "GET", "/_headers");
	const html = await (await fetch(s.base + "/")).text();
	for (const m of html.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)) await r(s, `static ${m[1]!.replace(/-[A-Za-z0-9_-]+\./, "-*.")}`, "GET", m[1]!);
	if (APP === "tumbler") await r(s, "static sw", "GET", "/sw.js");
}

// --- cross-database phase -----------------------------------------------------------------------------

async function crossCheck(s: Server, from: Impl, st: State, c: Ctx, fail: (m: string) => void) {
	const tag = `${s.impl} on ${from}'s database`;
	const ok = async (step: string, p: Promise<Out & { json: any }>, status = 200) => {
		const x = await p;
		if (x.status !== status) fail(`${tag}: ${step}: ${x.status} ${JSON.stringify(x.body)}`);
		return x;
	};
	await ok("session (cookie from other impl)", call(s, "", "GET", "/api/session", { jar: st.adminJar }));
	await ok("bob session", call(s, "", "GET", "/api/session", { jar: st.bobJar }));
	const pre = await ok("prelogin", call(s, "", "POST", "/api/prelogin", { body: { username: c.admin.username } }));
	await ok("password login", call(s, "", "POST", "/api/login", { body: { username: c.admin.username, authKey: await authKey({ password: "recovered pw" }, pre.json.kdf) } }));
	const bobKey = await authKey(c.bob, c.bob.material.kdf);
	while (totpCounter(Date.now()) + 1 <= st.bobLastStep) await Bun.sleep(1000);
	await ok("login TOTP sealed by other impl", call(s, "", "POST", "/api/login", { body: { username: c.bob.username, authKey: bobKey, totp: await totpCode(st.bobTotpSecret, 1) } }));
	const rk = toB64((await recoverySubkeys(parseRecoveryKey(c.admin.recoveryKey))).authKey);
	await ok("recovery key", call(s, "", "POST", "/api/recover/start", { body: { username: c.admin.username, recoveryAuthKey: rk } }));
	if (APP === "tumbler") {
		const pull = await ok("sync pull", call(s, "", "GET", "/api/sync", { jar: st.adminJar }));
		if (pull.json?.entries?.length !== 3) fail(`${tag}: expected 3 entries, got ${JSON.stringify(pull.body)}`);
	}
	if (APP === "coffer") await coffer.cross(s, st, ok);
}

// --- database comparison ------------------------------------------------------------------------------

const COMPARE: Record<string, string[]> = {
	tumbler: [
		"SELECT username, role, auth_verifier, kdf_salt, kdf_params, wrapped_vault_key, recovery_wrapped_key, recovery_verifier, login_totp_enabled, disabled FROM users ORDER BY username",
		"SELECT e.id, e.ciphertext, e.iv, e.revision, e.updated_at, e.deleted, e.seq FROM entries e JOIN users u ON u.id = e.user_id ORDER BY u.username, e.id",
		"SELECT key, count FROM rate_limits ORDER BY key",
		"SELECT u.username, a.event, a.meta IS NULL AS no_meta FROM audit_log a LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id",
		"SELECT name FROM d1_migrations ORDER BY id",
		"SELECT role, used_at IS NULL AS unused FROM invites ORDER BY created_at",
	],
};

function dbRows(dir: string, sql: string): unknown[] {
	const db = new Database(join(dir, `${APP}.sqlite`), { readonly: true });
	try {
		return db.query(sql).all();
	} finally {
		db.close();
	}
}

// --- coffer: dashboard and machine API --------------------------------------------------------------------
// Fixed IDs and placeholder ciphertext (the server only checks formats), so both runs write the same rows.

const P1 = "11111111-1111-4111-8111-111111111111";
const P2 = "22222222-2222-4222-8222-222222222222";
const E1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const E2 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2";
const E3 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3";
const MAC1 = "a".repeat(64);
const MAC2 = "b".repeat(64);
const RW_ID = "cfi_parityReadWrite0000000";
const RO_ID = "cfi_parityReadOnly00000000";
const sealedX = (n: number) => ({ iv: toB64(new Uint8Array(12).fill(n)), ct: toB64(new Uint8Array(48).fill(n)) });
const wrapX = (n: number) => ({ epk: toB64(new Uint8Array(65).fill(n)), ...sealedX(n) });
const machineKey = async (id: string) => toB64(await hkdf(utf8.encode(`secret-of-${id}`), "coffer/v1/machine-auth"));
const bearer = async (id: string) => ({ authorization: `Bearer ${id}.${await machineKey(id)}` });

const coffer = {
	async scenario(s: Server, st: State, out: Out[]) {
		const r = async (...a: Parameters<typeof call>) => {
			const x = await call(...a);
			out.push(x);
			return x;
		};
		const A = st.adminJar;
		const B = st.bobJar;
		await r(s, "keys none", "GET", "/api/keys", { jar: A });
		await r(s, "keys unauth", "GET", "/api/keys");
		await r(s, "keys bad", "PUT", "/api/keys", { body: { publicKey: "x" }, jar: A });
		await r(s, "keys put", "PUT", "/api/keys", { body: { publicKey: toB64(new Uint8Array(65).fill(7)), wrappedPrivateKey: sealedX(7) }, jar: A });
		await r(s, "keys again", "PUT", "/api/keys", { body: { publicKey: toB64(new Uint8Array(65).fill(7)), wrappedPrivateKey: sealedX(7) }, jar: A });
		await r(s, "keys get", "GET", "/api/keys", { jar: A });
		await r(s, "user key no keys", "GET", "/api/users/bob.b/key", { jar: A });
		await r(s, "keys put bob", "PUT", "/api/keys", { body: { publicKey: toB64(new Uint8Array(65).fill(8)), wrappedPrivateKey: sealedX(8) }, jar: B });
		const bk = await r(s, "user key", "GET", "/api/users/Bob.B/key", { jar: A });
		await r(s, "user key missing", "GET", "/api/users/nobody/key", { jar: A });
		await r(s, "user key invalid", "GET", "/api/users/a/key", { jar: A });
		await r(s, "users prefix", "GET", "/api/users", { jar: A });

		const proj = { id: P1, name: "  Billing  ", wrappedKey: wrapX(1), environments: [{ id: E1, name: "dev", wrappedKey: sealedX(2) }, { id: E2, name: "prod", wrappedKey: sealedX(3) }] };
		await r(s, "project bad envs", "POST", "/api/projects", { body: { ...proj, environments: [] }, jar: A });
		await r(s, "project dup envs", "POST", "/api/projects", { body: { ...proj, environments: [proj.environments[0], { ...proj.environments[1], name: "DEV" }] }, jar: A });
		await r(s, "project bad uuid", "POST", "/api/projects", { body: { ...proj, id: P1.toUpperCase() }, jar: A });
		await r(s, "project create", "POST", "/api/projects", { body: proj, jar: A });
		await r(s, "project conflict", "POST", "/api/projects", { body: proj, jar: A });
		await r(s, "project create 2", "POST", "/api/projects", { body: { ...proj, id: P2, name: "alpha", environments: [{ id: E3, name: "only", wrappedKey: sealedX(4) }] }, jar: A });
		await r(s, "projects", "GET", "/api/projects", { jar: A });
		await r(s, "project rename", "PATCH", `/api/projects/${P1}`, { body: { name: "Billing 2" }, jar: A });
		await r(s, "project not member", "PATCH", `/api/projects/${P1}`, { body: { name: "x" }, jar: B });
		await r(s, "project bad id", "PATCH", "/api/projects/nope", { body: { name: "x" }, jar: A });
		const E4 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4";
		await r(s, "env create", "POST", `/api/projects/${P1}/environments`, { body: { id: E4, name: "staging", wrappedKey: sealedX(5) }, jar: A });
		await r(s, "env exists", "POST", `/api/projects/${P1}/environments`, { body: { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5", name: "staging", wrappedKey: sealedX(5) }, jar: A });
		await r(s, "env bad name", "POST", `/api/projects/${P1}/environments`, { body: { id: E4, name: "-bad", wrappedKey: sealedX(5) }, jar: A });
		await r(s, "env rename", "PATCH", `/api/environments/${E4}`, { body: { name: "stage" }, jar: A });
		await r(s, "env rename conflict", "PATCH", `/api/environments/${E4}`, { body: { name: "dev" }, jar: A });
		await r(s, "env delete", "DELETE", `/api/environments/${E4}`, { jar: A });
		await r(s, "env delete last", "DELETE", `/api/environments/${E3}`, { jar: A });

		await r(s, "member add bad", "POST", `/api/projects/${P1}/members`, { body: { userId: bk.json.userId, role: "boss", wrappedKey: wrapX(6) }, jar: A });
		await r(s, "member add", "POST", `/api/projects/${P1}/members`, { body: { userId: bk.json.userId, wrappedKey: wrapX(6) }, jar: A });
		await r(s, "member add again", "POST", `/api/projects/${P1}/members`, { body: { userId: bk.json.userId, wrappedKey: wrapX(6) }, jar: A });
		await r(s, "members", "GET", `/api/projects/${P1}/members`, { jar: B });
		await r(s, "member owner only", "DELETE", `/api/projects/${P1}`, { jar: B });
		await r(s, "projects bob", "GET", "/api/projects", { jar: B });
		const me = (await call(s, "", "GET", "/api/session", { jar: A })).json.user.id;
		await r(s, "demote last owner", "PATCH", `/api/projects/${P1}/members/${me}`, { body: { role: "member" }, jar: A });
		await r(s, "promote bob", "PATCH", `/api/projects/${P1}/members/${bk.json.userId}`, { body: { role: "owner" }, jar: A });
		await r(s, "demote bob", "PATCH", `/api/projects/${P1}/members/${bk.json.userId}`, { body: { role: "member" }, jar: A });

		await r(s, "secret put", "PUT", `/api/environments/${E1}/secrets/${MAC1}`, { body: sealedX(10), jar: A });
		await r(s, "secret put v2", "PUT", `/api/environments/${E1}/secrets/${MAC1}`, { body: sealedX(11), jar: B });
		await r(s, "secret put 2", "PUT", `/api/environments/${E1}/secrets/${MAC2}`, { body: sealedX(12), jar: A });
		await r(s, "secret bad mac", "PUT", `/api/environments/${E1}/secrets/XYZ`, { body: sealedX(12), jar: A });
		await r(s, "secret bad body", "PUT", `/api/environments/${E1}/secrets/${MAC2}`, { body: { iv: "AAAA", ct: "AAAA" }, jar: A });
		await r(s, "secrets", "GET", `/api/environments/${E1}/secrets`, { jar: A });
		await r(s, "secret get", "GET", `/api/environments/${E1}/secrets/${MAC1}`, { jar: A });
		await r(s, "secret missing", "GET", `/api/environments/${E2}/secrets/${MAC1}`, { jar: A });
		await r(s, "secret delete", "DELETE", `/api/environments/${E1}/secrets/${MAC2}`, { jar: A });
		await r(s, "secret delete again", "DELETE", `/api/environments/${E1}/secrets/${MAC2}`, { jar: A });
		await r(s, "secret history", "GET", `/api/environments/${E1}/secrets/${MAC1}/history`, { jar: A });
		await r(s, "secret other env", "GET", `/api/environments/${E3}/secrets`, { jar: B });

		// Machine identities and the /api/v1 API.
		const ident = async (id: string, scope: string) => ({ id, envId: E1, name: `ci ${scope}`, scope, authKey: await machineKey(id), wrappedKey: sealedX(20) });
		await r(s, "identity bad scope", "POST", `/api/projects/${P1}/identities`, { body: { ...(await ident(RW_ID, "rw")) }, jar: A });
		await r(s, "identity bad id", "POST", `/api/projects/${P1}/identities`, { body: { ...(await ident("cfi_x", "write")) }, jar: A });
		await r(s, "identity env missing", "POST", `/api/projects/${P1}/identities`, { body: { ...(await ident(RW_ID, "write")), envId: E3 }, jar: A });
		await r(s, "identity create rw", "POST", `/api/projects/${P1}/identities`, { body: await ident(RW_ID, "write"), jar: A });
		await Bun.sleep(5); // identities list ORDER BY created_at: avoid a same-millisecond tie
		await r(s, "identity create ro", "POST", `/api/projects/${P1}/identities`, { body: await ident(RO_ID, "read"), jar: A });
		await r(s, "identity conflict", "POST", `/api/projects/${P1}/identities`, { body: await ident(RO_ID, "read"), jar: A });
		await r(s, "identity member", "POST", `/api/projects/${P1}/identities`, { body: await ident("cfi_parityMember0000000000", "read"), jar: B });
		await r(s, "identities", "GET", `/api/projects/${P1}/identities`, { jar: A });
		await r(s, "v1 no auth", "GET", "/api/v1/identity");
		await r(s, "v1 bad bearer", "GET", "/api/v1/identity", { headers: { authorization: "Bearer nope" } });
		await r(s, "v1 wrong key", "GET", "/api/v1/identity", { headers: { authorization: `Bearer ${RW_ID}.${toB64(new Uint8Array(32))}` } });
		await r(s, "v1 identity", "GET", "/api/v1/identity", { headers: await bearer(RW_ID) });
		await r(s, "v1 secrets", "GET", "/api/v1/secrets", { headers: await bearer(RO_ID) });
		await r(s, "v1 secret get", "GET", `/api/v1/secrets/${MAC1}`, { headers: await bearer(RO_ID) });
		await r(s, "v1 secret bad mac", "GET", "/api/v1/secrets/nope", { headers: await bearer(RO_ID) });
		await r(s, "v1 secret missing", "GET", `/api/v1/secrets/${MAC2}`, { headers: await bearer(RO_ID) });
		await r(s, "v1 put read-only", "PUT", `/api/v1/secrets/${MAC2}`, { body: sealedX(30), headers: await bearer(RO_ID) });
		await r(s, "v1 put", "PUT", `/api/v1/secrets/${MAC2}`, { body: sealedX(30), headers: await bearer(RW_ID) });
		await r(s, "v1 put v2", "PUT", `/api/v1/secrets/${MAC2}`, { body: sealedX(31), headers: await bearer(RW_ID) });
		await r(s, "v1 delete", "DELETE", `/api/v1/secrets/${MAC2}`, { headers: await bearer(RW_ID) });
		await r(s, "v1 delete again", "DELETE", `/api/v1/secrets/${MAC2}`, { headers: await bearer(RW_ID) });
		await r(s, "history machine", "GET", `/api/environments/${E1}/secrets/${MAC2}/history`, { jar: A });
		await r(s, "v1 unknown", "GET", "/api/v1/nope", { headers: await bearer(RW_ID) });
		await r(s, "identity revoke member", "DELETE", `/api/identities/${RO_ID}`, { jar: B });
		await r(s, "identity revoke", "DELETE", `/api/identities/${RO_ID}`, { jar: A });
		await r(s, "v1 revoked", "GET", "/api/v1/identity", { headers: await bearer(RO_ID) });
		await r(s, "identity revoke again", "DELETE", `/api/identities/${RO_ID}`, { jar: A });
		for (let i = 0; i < 30; i++) await call(s, "", "GET", "/api/v1/identity", { headers: { authorization: `Bearer ${RO_ID}.${toB64(new Uint8Array(32))}`, "x-forwarded-for": "10.0.0.9" } });
		await r(s, "v1 rate limited", "GET", "/api/v1/identity", { headers: { ...(await bearer(RO_ID)), "x-forwarded-for": "10.0.0.9" } });
		await r(s, "member leave", "DELETE", `/api/projects/${P1}/members/${bk.json.userId}`, { jar: B });
		await r(s, "project delete", "DELETE", `/api/projects/${P2}`, { jar: A });
		await r(s, "projects after", "GET", "/api/projects", { jar: A });
	},
	async cross(s: Server, _st: State, ok: (step: string, p: Promise<Out & { json: any }>, status?: number) => Promise<Out & { json: any }>) {
		await ok("v1 identity (verifier from other impl)", call(s, "", "GET", "/api/v1/identity", { headers: await bearer(RW_ID) }));
		const list = await ok("v1 secrets", call(s, "", "GET", "/api/v1/secrets", { headers: await bearer(RW_ID) }));
		if (list.json?.secrets?.length !== 1) throw new Error(`expected 1 secret, got ${JSON.stringify(list.body)}`);
		await ok("v1 put", call(s, "", "PUT", `/api/v1/secrets/${MAC2}`, { body: sealedX(40), headers: await bearer(RW_ID) }));
	},
	compare: [
		"SELECT id, name, created_at > 0 AS t FROM projects ORDER BY id",
		"SELECT id, project_id, name, position, wrapped_key FROM environments ORDER BY id",
		"SELECT p.project_id, u.username, p.role, p.wrapped_key FROM project_members p JOIN users u ON u.id = p.user_id ORDER BY 1, 2",
		"SELECT u.username, k.public_key, k.wrapped_private_key FROM user_keys k JOIN users u ON u.id = k.user_id ORDER BY 1",
		"SELECT env_id, name_mac, iv, ct, version FROM secrets ORDER BY 1, 2",
		"SELECT env_id, name_mac, iv, ct, version, deleted, replaced_by LIKE 'machine:%' AS m FROM secret_history ORDER BY id",
		"SELECT id, project_id, env_id, name, scope, auth_verifier, wrapped_key, revoked_at IS NULL AS live, last_used_at IS NULL AS unused FROM machine_identities ORDER BY id",
	] as string[],
};

// --- main ---------------------------------------------------------------------------------------------

async function main() {
	const tmp = mkdtempSync(join(tmpdir(), `parity-${APP}-`));
	const dirs = { ts: join(tmp, "ts"), rs: join(tmp, "rs") };
	const failures: string[] = [];
	const fail = (m: string) => failures.push(m);
	try {
		const vaultKey = generateVaultKey();
		const c: Ctx = {
			admin: await person("alice", "correct horse"),
			bob: await person("bob.b", "battery staple"),
			newPassword: await makePasswordMaterial("new pw", vaultKey, 100_000),
			recoveryPassword: await makePasswordMaterial("recovered pw", vaultKey, 100_000),
			vaultKey,
		};
		const outs: Record<Impl, Out[]> = { ts: [], rs: [] };
		const states = {} as Record<Impl, State>;
		for (const impl of ["ts", "rs"] as Impl[]) {
			const s = await start(impl, dirs[impl]);
			try {
				states[impl] = APP === "tumbler" ? await tumblerScenario(s, c, outs[impl]) : await accountsScenario(s, c, outs[impl]);
				if (APP === "coffer") await coffer.scenario(s, states[impl], outs[impl]);
				await staticScenario(s, outs[impl]);
			} catch (e) {
				console.error(`${impl} scenario failed; last responses:`);
				for (const o of outs[impl].slice(-6)) console.error(JSON.stringify(maskOut(o)));
				console.error(s.log.join("").slice(-2000));
				throw e;
			} finally {
				await stop(s);
			}
		}

		// 2. responses
		const n = Math.max(outs.ts.length, outs.rs.length);
		let diffs = 0;
		for (let i = 0; i < n; i++) {
			const t = outs.ts[i] && maskOut(outs.ts[i]!);
			const r = outs.rs[i] && maskOut(outs.rs[i]!);
			if (JSON.stringify(t) !== JSON.stringify(r)) {
				diffs++;
				fail(`response #${i} "${t?.step ?? r?.step}"\n    ts: ${JSON.stringify(t)}\n    rs: ${JSON.stringify(r)}`);
			}
		}
		console.log(`responses: ${n} compared, ${diffs} different`);

		// 3. databases
		for (const sql of [...(COMPARE[APP] ?? COMPARE.tumbler!.filter((q) => !q.includes("entries"))), ...coffer.compare]) {
			const a = JSON.stringify(dbRows(dirs.ts, sql));
			const b = JSON.stringify(dbRows(dirs.rs, sql));
			if (a !== b) fail(`database: ${sql}\n    ts: ${a.slice(0, 600)}\n    rs: ${b.slice(0, 600)}`);
		}
		console.log("databases: compared");

		// 4. swap databases
		for (const [impl, from] of [["rs", "ts"], ["ts", "rs"]] as [Impl, Impl][]) {
			const dir = join(tmp, `${impl}-on-${from}`);
			cpSync(dirs[from], dir, { recursive: true });
			const s = await start(impl, dir);
			await crossCheck(s, from, states[from], c, fail);
			await stop(s);
			if (!s.log.join("").includes("SIGTERM: finishing open requests")) fail(`${impl}: no graceful shutdown log`);
		}
		console.log("cross-database: checked");
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
	if (failures.length) {
		console.error(`\n${failures.length} problem(s):\n- ${failures.join("\n- ")}`);
		process.exit(1);
	}
	console.log(`\n${APP}: TypeScript and Rust standalone servers match.`);
}

await main();
