// End-to-end check of the Tumbler API against a running server with an EMPTY database.
// Usage: bun run scripts/api-smoke.ts <base url> <ADMIN_SETUP_TOKEN>
// Creates real accounts, so never point it at a server with real users.

import {
	deriveKeys,
	generateVaultKey,
	makeAccountMaterial,
	makePasswordMaterial,
	parseRecoveryKey,
	recoverySubkeys,
	sealJSON,
	importAesKey,
	timingSafeEqual,
	toB64,
	unwrapVaultKey,
	unwrapWithRecovery,
	type KdfParams,
	type Sealed,
} from "@cfsa/crypto";
import { base32Decode, hotp, importOtpKey, totpCounter } from "@cfsa/totp";

const [base, setupToken] = process.argv.slice(2);
if (!base || !setupToken) {
	console.error("Usage: bun run scripts/api-smoke.ts <base url> <ADMIN_SETUP_TOKEN>");
	process.exit(2);
}
const IT = 100_000; // server minimum; keeps the script quick

let failures = 0;
function check(cond: unknown, what: string) {
	if (cond) console.log(`✓ ${what}`);
	else {
		failures++;
		console.log(`✗ ${what}`);
	}
}

class Client {
	cookie = "";
	async call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
		const res = await fetch(`${base}/api${path}`, {
			method,
			headers: { ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(this.cookie ? { Cookie: this.cookie } : {}), ...headers },
			body: body === undefined ? undefined : JSON.stringify(body),
		});
		const set = res.headers.get("Set-Cookie");
		if (set) this.cookie = set.split(";")[0]!;
		const text = await res.text();
		let json: any = null;
		try {
			json = JSON.parse(text);
		} catch {
			json = { raw: text };
		}
		return { status: res.status, json };
	}
}

async function login(c: Client, username: string, password: string, totp?: string) {
	const pre = await c.call("POST", "/prelogin", { username });
	const kdf = pre.json.kdf as KdfParams;
	const { authKey, wrapKey } = await deriveKeys(password, kdf);
	const r = await c.call("POST", "/login", { username, authKey: toB64(authKey), ...(totp ? { totp } : {}) });
	return { ...r, wrapKey, authKey: toB64(authKey) };
}

const anon = new Client();
const admin = new Client();
const bob = new Client();

// --- setup
let r = await anon.call("GET", "/setup");
check(r.json.needed === true && r.json.tokenConfigured === true, "setup needed on empty server");
const adminVk = generateVaultKey();
const adminAcct = await makeAccountMaterial("admin long password", adminVk, IT);
r = await anon.call("POST", "/setup", { setupToken: "x".repeat(40), username: "admin", ...adminAcct.material });
check(r.status === 403, "setup with wrong token → 403");
r = await admin.call("POST", "/setup", { setupToken, username: "Admin", ...adminAcct.material });
check(r.status === 200 && r.json.user.role === "admin" && r.json.user.username === "admin", "setup creates admin (username lowercased)");
r = await anon.call("POST", "/setup", { setupToken, username: "admin2", ...adminAcct.material });
check(r.status === 409, "second setup → 409");
r = await admin.call("GET", "/session");
check(r.status === 200 && r.json.user.username === "admin", "session cookie works");

// --- prelogin
const p1 = await anon.call("POST", "/prelogin", { username: "nobody" });
const p2 = await anon.call("POST", "/prelogin", { username: "nobody" });
const p3 = await anon.call("POST", "/prelogin", { username: "someone" });
const pa = await anon.call("POST", "/prelogin", { username: "admin" });
check(p1.json.kdf.salt === p2.json.kdf.salt && p1.json.kdf.salt !== p3.json.kdf.salt, "decoy salt is stable per unknown username");
check(pa.json.kdf.salt === adminAcct.material.kdf.salt, "prelogin returns real kdf for existing user");

// --- login
r = await login(new Client(), "admin", "wrong password!!");
check(r.status === 401 && r.json.error === "invalid_credentials", "wrong password → 401");
r = await login(new Client(), "admin", "admin long password");
check(r.status === 200 && timingSafeEqual(await unwrapVaultKey(r.wrapKey, r.json.wrappedVaultKey), adminVk), "login returns wrapped vault key that unwraps");

// --- invites + register
r = await admin.call("POST", "/admin/invites", { role: "user" });
const invite = r.json.token as string;
check(r.status === 200 && typeof invite === "string", "admin creates invite");
r = await anon.call("GET", `/invites/check?token=${invite}`);
check(r.json.valid === true, "invite check: valid");
const bobVk = generateVaultKey();
let bobAcct = await makeAccountMaterial("bob first password", bobVk, IT);
r = await bob.call("POST", "/register", { invite: "nope", username: "bob", ...bobAcct.material });
check(r.status === 403, "register with bad invite → 403");
r = await bob.call("POST", "/register", { invite, username: "bob", ...bobAcct.material });
check(r.status === 200 && r.json.user.role === "user", "register with invite");
r = await anon.call("POST", "/register", { invite, username: "eve", ...bobAcct.material });
check(r.status === 403, "invite is single-use");
r = await anon.call("GET", `/invites/check?token=${invite}`);
check(r.json.valid === false, "invite check: used");
r = await bob.call("GET", "/admin/invites");
check(r.status === 403, "non-admin cannot list invites");
r = await admin.call("GET", "/admin/invites");
check(r.json.invites?.[0]?.usedBy === "bob", "admin sees invite used by bob");

// --- sync
const key = await importAesKey(bobVk);
const enc = (v: unknown) => sealJSON(key, v);
const e1 = await enc({ issuer: "A" });
const e2 = await enc({ issuer: "B" });
r = await bob.call("POST", "/sync", { changes: [
	{ id: "e1", ...e1, revision: 1, updatedAt: 1000, deleted: false },
	{ id: "e2", ...e2, revision: 1, updatedAt: 1000, deleted: false },
] });
check(r.json.results?.every((x: any) => x.accepted), "push 2 entries");
r = await bob.call("GET", "/sync?since=0");
const cursor = r.json.cursor;
check(r.json.entries.length === 2 && cursor === 2, "pull returns 2, cursor 2");
r = await bob.call("POST", "/sync", { changes: [{ id: "e1", ...(await enc({ issuer: "old" })), revision: 2, updatedAt: 500, deleted: false }] });
check(r.json.results[0].accepted === false, "older change is rejected (last-write-wins)");
r = await bob.call("POST", "/sync", { changes: [{ id: "e1", iv: "", ct: "", revision: 2, updatedAt: 2000, deleted: true }] });
check(r.json.results[0].accepted === true, "newer tombstone accepted");
r = await bob.call("GET", `/sync?since=${cursor}`);
check(r.json.entries.length === 1 && r.json.entries[0].deleted === true && r.json.cursor === 3, "pull since cursor returns only the change");
r = await admin.call("GET", "/sync?since=0");
check(r.json.entries.length === 0, "users cannot see each other's entries");
r = await anon.call("GET", "/sync?since=0");
check(r.status === 401, "sync requires session");

r = await bob.call("POST", "/sync", { changes: [{ id: "e9", ...e1, revision: 1, updatedAt: Date.now() + 7 * 86_400_000, deleted: false }] });
check(r.status === 400, "far-future updatedAt rejected");

// --- CSRF guards
r = await bob.call("POST", "/sync", { changes: [] }, { Origin: "https://evil.example" });
check(r.status === 403, "cross-origin POST → 403");
r = await bob.call("POST", "/logout", undefined, { "Content-Type": "text/plain" });
check(r.status === 415, "non-JSON POST → 415");

// --- password change
const newPw = await makePasswordMaterial("bob second password", bobVk, IT);
const bobOld = await deriveKeys("bob first password", bobAcct.material.kdf);
r = await bob.call("POST", "/account/password", { currentAuthKey: toB64(bobOld.authKey), ...newPw });
check(r.status === 200, "password change");
r = await login(new Client(), "bob", "bob first password");
check(r.status === 401, "old password no longer works");
r = await login(new Client(), "bob", "bob second password");
check(r.status === 200, "new password works");

// --- login TOTP
r = await bob.call("POST", "/account/totp/setup", {});
const secret = r.json.secret as string;
check(typeof secret === "string" && r.json.uri.startsWith("otpauth://totp/"), "TOTP setup returns secret + otpauth URI");
const totpKey = await importOtpKey(base32Decode(secret));
const code = await hotp(totpKey, totpCounter(Date.now()));
r = await bob.call("POST", "/account/totp/enable", { code: "000000" === code ? "111111" : "000000" });
check(r.status === 400, "enable with wrong code → 400");
r = await bob.call("POST", "/account/totp/enable", { code });
check(r.status === 200, "enable with correct code");
r = await login(new Client(), "bob", "bob second password");
check(r.status === 401 && r.json.error === "totp_required", "login now requires TOTP");
r = await login(new Client(), "bob", "bob second password", code);
check(r.status === 401 && r.json.error === "invalid_totp", "same TOTP code cannot be reused");
const next = await hotp(totpKey, totpCounter(Date.now()) + 1);
r = await login(new Client(), "bob", "bob second password", next);
check(r.status === 200, "login with fresh TOTP code (next step)");

// --- recovery
const rk = parseRecoveryKey(bobAcct.recoveryKey);
const rsub = await recoverySubkeys(rk);
r = await anon.call("POST", "/recover/start", { username: "bob", recoveryAuthKey: toB64(new Uint8Array(32)) });
check(r.status === 401, "recovery with wrong key → 401");
r = await anon.call("POST", "/recover/start", { username: "bob", recoveryAuthKey: toB64(rsub.authKey) });
const recovered = await unwrapWithRecovery(rk, r.json.recoveryWrappedKey as Sealed);
check(timingSafeEqual(recovered, bobVk), "recovery key unwraps the same vault key");
const pw3 = await makePasswordMaterial("bob third password", recovered, IT);
const rec = new Client();
r = await rec.call("POST", "/recover/finish", { username: "bob", recoveryAuthKey: toB64(rsub.authKey), ...pw3 });
check(r.status === 200 && r.json.totpEnabled === false, "recovery sets new password and disables login TOTP");
r = await bob.call("GET", "/session");
check(r.status === 401, "recovery signs out other sessions");
r = await login(new Client(), "bob", "bob third password");
check(r.status === 200, "login with recovered password");

// --- rate limiting
let last = 0;
for (let i = 0; i < 11; i++) last = (await login(new Client(), "admin", `wrong password ${i}`)).status;
check(last === 429, "repeated failures → 429");

console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
