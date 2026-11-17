#!/usr/bin/env bun
// Compares two standalone servers serving the same data, typically the live TypeScript server and a Rust
// candidate started on a copy of its data directory (see docs/rust-port.md). Sends only requests that
// never write on either server: health, setup status, pre-login (real and decoy usernames), unauthenticated
// and malformed API calls, and static files. Prints counts and differences; hides per-user responses.
//
//   bun scripts/standalone-compare.ts <live url> <candidate url> <copy of the database (read-only)>

import { Database } from "bun:sqlite";

const [live, cand, dbPath] = process.argv.slice(2);
if (!live || !cand || !dbPath) {
	console.error("Usage: bun scripts/standalone-compare.ts <live url> <candidate url> <database copy>");
	process.exit(2);
}
const H = { "cf-connecting-ip": "203.0.113.77", "x-forwarded-for": "203.0.113.77" };
const SKIP = new Set(["date", "connection", "keep-alive", "content-length", "transfer-encoding"]);
let same = 0;
let diff = 0;

const mask = (v: unknown): unknown =>
	typeof v === "number" && v > 1e12
		? "<ts>"
		: Array.isArray(v)
			? v.map(mask)
			: v && typeof v === "object"
				? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mask(x)]))
				: v;

async function one(base: string, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
	const res = await fetch(base + path, {
		method,
		headers: { ...H, ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers },
		body: body === undefined ? undefined : JSON.stringify(body),
		decompress: false,
	} as RequestInit);
	const h: Record<string, string> = {};
	res.headers.forEach((v, k) => {
		if (!SKIP.has(k)) h[k] = v;
	});
	const buf = new Uint8Array(await res.arrayBuffer());
	const json = (res.headers.get("content-type") ?? "").includes("json") && buf.length > 0;
	const b = json ? mask(JSON.parse(new TextDecoder().decode(buf))) : new Bun.CryptoHasher("sha256").update(buf).digest("hex").slice(0, 16);
	return JSON.stringify({ status: res.status, headers: h, body: b });
}

async function cmp(label: string, method: string, path: string, o: { body?: unknown; headers?: Record<string, string>; hide?: boolean } = {}) {
	const [a, b] = await Promise.all([one(live, method, path, o.body, o.headers), one(cand, method, path, o.body, o.headers)]);
	if (a === b) return void same++;
	diff++;
	console.log(`DIFF ${label}\n  live      ${o.hide ? "<hidden>" : a}\n  candidate ${o.hide ? "<hidden>" : b}`);
}

const db = new Database(dbPath, { readonly: true });
const users = db.query("SELECT username FROM users").all() as { username: string }[];
const hasMachines = !!db.query("SELECT 1 FROM sqlite_master WHERE name = 'machine_identities'").get();
const idents = hasMachines ? (db.query("SELECT id FROM machine_identities").all() as { id: string }[]) : [];
db.close();

await cmp("health", "GET", "/api/health");
await cmp("setup status (tokenConfigured differs if live started before its first user)", "GET", "/api/setup");
await cmp("session", "GET", "/api/session");
await cmp("not found", "GET", "/api/nope");
await cmp("csrf", "POST", "/api/prelogin", { body: { username: "x" }, headers: { origin: "https://evil.example" } });
await cmp("json required", "POST", "/api/prelogin", { headers: { "content-type": "text/plain" } });
// Decoy salts are HMACs keyed by SERVER_SECRET: equal output proves the candidate reads the same secret.
for (const n of ["nobody", "compare-check", "zz.decoy"]) await cmp(`decoy prelogin ${n}`, "POST", "/api/prelogin", { body: { username: n } });
for (const u of users) await cmp("prelogin existing user", "POST", "/api/prelogin", { body: { username: u.username }, hide: true });
if (hasMachines) {
	await cmp("projects unauthenticated", "GET", "/api/projects");
	await cmp("v1 no auth", "GET", "/api/v1/identity");
	await cmp("v1 malformed bearer", "GET", "/api/v1/secrets", { headers: { authorization: "Bearer nope" } });
	// Malformed keys are rejected before the rate limiter, so these do not write.
	for (const i of idents) await cmp("v1 malformed key for a real client ID", "GET", "/api/v1/identity", { headers: { authorization: `Bearer ${i.id}.short` }, hide: true });
} else {
	await cmp("sync unauthenticated", "GET", "/api/sync");
}
await cmp("static /", "GET", "/");
await cmp("static / br", "GET", "/", { headers: { "accept-encoding": "br, gzip" } });
await cmp("static SPA route", "GET", "/some/client/route");
await cmp("static missing file", "GET", "/missing.png");
const html = await (await fetch(live + "/")).text();
for (const m of html.matchAll(/(?:src|href)="(\/[^"]+)"/g)) await cmp(`static ${m[1]}`, "GET", m[1]!);

console.log(`${same} identical, ${diff} different (${users.length} users${hasMachines ? `, ${idents.length} client IDs` : ""})`);
for (const [name, base] of [["live", live], ["candidate", cand]] as const) {
	const t = performance.now();
	for (let i = 0; i < 300; i++) await (await fetch(base + "/api/health", { headers: H })).arrayBuffer();
	console.log(`${name}: 300 sequential /api/health in ${(performance.now() - t).toFixed(0)} ms`);
}
process.exit(diff ? 1 : 0);
