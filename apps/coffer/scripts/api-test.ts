// End-to-end check of the Coffer API and the TypeScript SDK against a running server with an EMPTY
// database. Usage: bun run scripts/api-test.ts <base url> <ADMIN_SETUP_TOKEN>
// Creates real accounts, so never point it at a server with real users.
//
// With SDK_CREDENTIALS_OUT=<file>, also writes a .env file with a read-write client ID for the
// dev environment, so the other language snippets can be tested against the same server.

import { deriveKeys, generateVaultKey, makeAccountMaterial, toB64, unwrapVaultKey, type KdfParams } from "@cfsa/crypto";
import { writeFileSync } from "node:fs";
import { Coffer, CofferError } from "../sdk/coffer.ts";
import {
	envCrypto,
	generateUserKeys,
	newKey,
	newMachineCredentials,
	unwrapEnvKey,
	unwrapMemberKey,
	unwrapPrivateKey,
	wrapEnvKey,
	wrapForMember,
} from "../web/lib/keys.ts";

const [base, setupToken] = process.argv.slice(2);
if (!base || !setupToken) {
	console.error("Usage: bun run scripts/api-test.ts <base url> <ADMIN_SETUP_TOKEN>");
	process.exit(2);
}
const IT = 100_000;

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
		let json: any;
		try {
			json = JSON.parse(text);
		} catch {
			json = { raw: text };
		}
		return { status: res.status, json };
	}
}

async function login(c: Client, username: string, password: string) {
	const pre = await c.call("POST", "/prelogin", { username });
	const { authKey, wrapKey } = await deriveKeys(password, pre.json.kdf as KdfParams);
	const r = await c.call("POST", "/login", { username, authKey: toB64(authKey) });
	return { ...r, vaultKey: r.status === 200 ? await unwrapVaultKey(wrapKey, r.json.wrappedVaultKey) : null };
}

const uuid = () => crypto.randomUUID();
const anon = new Client();
const alice = new Client();
const bob = new Client();

// --- accounts (shared package; smoke only) -----------------------------------------------------------
let r = await anon.call("GET", "/setup");
check(r.json.needed === true, "setup needed on empty server");
const aliceAcct = await makeAccountMaterial("alice long password", generateVaultKey(), IT);
r = await alice.call("POST", "/setup", { setupToken, username: "alice", ...aliceAcct.material });
check(r.status === 200 && r.json.user.role === "admin", "setup creates admin alice");
check(alice.cookie.startsWith("__Host-coffer_session="), "Coffer session cookie name");
const aliceLogin = await login(alice, "alice", "alice long password");
check(aliceLogin.status === 200, "alice logs in");
const aliceId = aliceLogin.json.user.id as string;
const aliceVk = aliceLogin.vaultKey!;

// --- user keys ---------------------------------------------------------------------------------------
r = await alice.call("GET", "/keys");
check(r.json.publicKey === null, "no key pair yet");
const aliceKeys = await generateUserKeys(aliceVk, aliceId);
r = await alice.call("PUT", "/keys", aliceKeys);
check(r.status === 200, "alice uploads key pair");
r = await alice.call("PUT", "/keys", aliceKeys);
check(r.status === 409, "key pair is set once");
r = await alice.call("GET", "/keys");
const alicePriv = await unwrapPrivateKey(aliceVk, aliceId, r.json.wrappedPrivateKey);
check(r.json.publicKey === aliceKeys.publicKey && alicePriv.type === "private", "private key unwraps with vault key");

// --- project -----------------------------------------------------------------------------------------
const projectId = uuid();
const projectKey = newKey();
const envs = [
	{ id: uuid(), name: "dev", key: newKey() },
	{ id: uuid(), name: "prod", key: newKey() },
];
r = await alice.call("POST", "/projects", {
	id: projectId,
	name: "Shop",
	wrappedKey: await wrapForMember(projectKey, aliceKeys.publicKey, projectId, aliceId),
	environments: await Promise.all(envs.map(async (e) => ({ id: e.id, name: e.name, wrappedKey: await wrapEnvKey(projectKey, e.key, e.id) }))),
});
check(r.status === 200, "create project with dev and prod");
r = await anon.call("GET", "/projects");
check(r.status === 401, "projects need a session");
r = await alice.call("GET", "/projects");
const p = r.json.projects?.[0];
check(p?.name === "Shop" && p.role === "owner" && p.environments.length === 2, "list projects");
const pk = await unwrapMemberKey(alicePriv, p.wrappedKey, projectId, aliceId);
const devKey = await unwrapEnvKey(pk, p.environments[0].wrappedKey, p.environments[0].id);
check(toB64(devKey) === toB64(envs[0]!.key), "project key → environment key round trip");

// --- secrets via dashboard API -------------------------------------------------------------------------
const dev = await envCrypto(envs[0]!.id, envs[0]!.key);
const prod = await envCrypto(envs[1]!.id, envs[1]!.key);
for (const [name, value] of [["DATABASE_URL", "postgres://dev"], ["API_TOKEN", "dev-token"]] as const) {
	const s = await dev.seal(name, value);
	r = await alice.call("PUT", `/environments/${dev.envId}/secrets/${s.mac}`, { iv: s.iv, ct: s.ct });
}
check(r.status === 200 && r.json.version === 1, "write secrets to dev");
const ps = await prod.seal("DATABASE_URL", "postgres://prod");
await alice.call("PUT", `/environments/${prod.envId}/secrets/${ps.mac}`, { iv: ps.iv, ct: ps.ct });
r = await alice.call("GET", `/environments/${dev.envId}/secrets`);
const names = (await Promise.all(r.json.secrets.map((row: any) => dev.open(row)))).map((s) => s.name).sort();
check(names.join(",") === "API_TOKEN,DATABASE_URL", "list + decrypt dev secrets");
check(!JSON.stringify(r.json).includes("DATABASE_URL"), "server response has no plaintext names");
const swapped = { ...r.json.secrets[0], mac: r.json.secrets[1].mac };
check(await dev.open(swapped).then(() => false, () => true), "ciphertext moved to another name fails to decrypt");

// --- machine identities ----------------------------------------------------------------------------
const rw = await newMachineCredentials(envs[0]!.key);
r = await alice.call("POST", `/projects/${projectId}/identities`, { id: rw.clientId, envId: dev.envId, name: "ci", scope: "write", authKey: rw.authKey, wrappedKey: rw.wrappedKey });
check(r.status === 200, "create read-write client ID for dev");
const ro = await newMachineCredentials(envs[1]!.key);
r = await alice.call("POST", `/projects/${projectId}/identities`, { id: ro.clientId, envId: prod.envId, name: "web", scope: "read", authKey: ro.authKey, wrappedKey: ro.wrappedKey });
check(r.status === 200, "create read-only client ID for prod");

const sdk = new Coffer(base, rw.clientId, rw.clientSecret);
check((await sdk.identity()).environment === "dev", "SDK identity: dev");
let all = await sdk.listAllSecrets();
check(all.DATABASE_URL === "postgres://dev" && all.API_TOKEN === "dev-token" && Object.keys(all).length === 2, "SDK listAllSecrets");
check((await sdk.getSecret("DATABASE_URL")) === "postgres://dev", "SDK getSecret");
check((await sdk.getSecret("MISSING")) === undefined, "SDK getSecret of a missing name → undefined");
check((await sdk.writeSecret("DATABASE_URL", "postgres://dev2")) === 2, "SDK writeSecret replaces (version 2)");
check((await sdk.writeSecret("NEW_ONE", "ünïcødé ✓ \"quoted\"\nline2")) === 1, "SDK writeSecret creates");
check((await sdk.getSecret("NEW_ONE")) === "ünïcødé ✓ \"quoted\"\nline2", "unicode and newlines round trip");
check((await sdk.deleteSecret("API_TOKEN")) === true && (await sdk.deleteSecret("API_TOKEN")) === false, "SDK deleteSecret");
r = await alice.call("GET", `/environments/${dev.envId}/secrets`);
all = Object.fromEntries((await Promise.all(r.json.secrets.map((row: any) => dev.open(row)))).map((s) => [s.name, s.value]));
check(all.DATABASE_URL === "postgres://dev2" && all.NEW_ONE && !all.API_TOKEN, "dashboard sees SDK writes");
r = await alice.call("GET", `/environments/${dev.envId}/secrets/${await dev.mac("DATABASE_URL")}/history`);
check(r.json.history?.length === 1 && r.json.history[0].version === 1, "history keeps the previous version");

const roSdk = new Coffer(base, ro.clientId, ro.clientSecret);
check((await roSdk.getSecret("DATABASE_URL")) === "postgres://prod", "read-only client reads prod");
const err = await roSdk.writeSecret("X", "y").then(() => null, (e) => e);
check(err instanceof CofferError && err.status === 403, "read-only client cannot write → 403");
const bad = await new Coffer(base, rw.clientId, `cfs_${"A".repeat(43)}`).listAllSecrets().then(() => null, (e) => e);
check(bad instanceof CofferError && bad.status === 401, "wrong client secret → 401");
const raw = await fetch(`${base}/api/v1/secrets`, { headers: { Authorization: "Bearer nope" } });
check(raw.status === 401, "malformed Authorization → 401");

// Node.js runs the SDK file directly (type stripping) and reads the environment.
const node = Bun.spawnSync(["node", "--input-type=module", "-e", `import { Coffer } from ${JSON.stringify(new URL("../sdk/coffer.ts", import.meta.url).pathname)}; const c = Coffer.fromEnv(); console.log(JSON.stringify(await c.listAllSecrets()));`], {
	env: { ...process.env, COFFER_URL: base, COFFER_CLIENT_ID: rw.clientId, COFFER_CLIENT_SECRET: rw.clientSecret },
});
const nodeOut = node.stdout.toString().trim();
check(node.exitCode === 0 && JSON.parse(nodeOut || "{}").DATABASE_URL === "postgres://dev2", `Node.js runs sdk/coffer.ts with fromEnv()${node.exitCode ? `: ${node.stderr}` : ""}`);

// --- sharing with another user ---------------------------------------------------------------------
r = await alice.call("POST", "/admin/invites", {});
const invite = r.json.token;
const bobAcct = await makeAccountMaterial("bob long password", generateVaultKey(), IT);
r = await bob.call("POST", "/register", { invite, username: "bob", ...bobAcct.material });
check(r.status === 200, "bob registers with invite");
r = await alice.call("GET", "/users/bob/key");
check(r.status === 409, "cannot share with a user who has no key pair");
const bobLogin = await login(bob, "bob", "bob long password");
const bobId = bobLogin.json.user.id as string;
const bobKeys = await generateUserKeys(bobLogin.vaultKey!, bobId);
await bob.call("PUT", "/keys", bobKeys);
r = await bob.call("GET", `/environments/${dev.envId}/secrets`);
check(r.status === 404, "non-member cannot read secrets (404)");
r = await alice.call("GET", "/users/bob/key");
check(r.json.publicKey === bobKeys.publicKey, "alice fetches bob's public key");
r = await alice.call("POST", `/projects/${projectId}/members`, { userId: bobId, role: "member", wrappedKey: await wrapForMember(pk, r.json.publicKey, projectId, bobId) });
check(r.status === 200, "alice adds bob as member");
r = await bob.call("GET", "/projects");
const bp = r.json.projects?.[0];
const bobPriv = await unwrapPrivateKey(bobLogin.vaultKey!, bobId, bobKeys.wrappedPrivateKey);
const bobPk = await unwrapMemberKey(bobPriv, bp.wrappedKey, projectId, bobId);
const bobDev = await envCrypto(dev.envId, await unwrapEnvKey(bobPk, bp.environments.find((e: any) => e.id === dev.envId).wrappedKey, dev.envId));
r = await bob.call("GET", `/environments/${dev.envId}/secrets/${await bobDev.mac("DATABASE_URL")}`);
check((await bobDev.open(r.json)).value === "postgres://dev2", "bob decrypts a shared secret");
r = await bob.call("POST", `/projects/${projectId}/identities`, { id: ro.clientId, envId: dev.envId, name: "x", scope: "read", authKey: ro.authKey, wrappedKey: ro.wrappedKey });
check(r.status === 403, "members cannot create client IDs");
r = await bob.call("DELETE", `/projects/${projectId}`);
check(r.status === 403, "members cannot delete the project");
r = await alice.call("DELETE", `/projects/${projectId}/members/${aliceId}`);
check(r.status === 400 && r.json.error === "last_owner", "last owner cannot leave");

// --- revoke ---------------------------------------------------------------------------------------
r = await alice.call("GET", `/projects/${projectId}/identities`);
check(r.json.identities?.length === 2, "list client IDs");
r = await alice.call("DELETE", `/identities/${ro.clientId}`);
check(r.status === 200, "revoke read-only client ID");
const revoked = await new Coffer(base, ro.clientId, ro.clientSecret).listAllSecrets().then(() => null, (e) => e);
check(revoked instanceof CofferError && revoked.status === 401, "revoked client ID → 401");

if (process.env.SDK_CREDENTIALS_OUT) {
	writeFileSync(process.env.SDK_CREDENTIALS_OUT, `COFFER_URL=${base}\nCOFFER_CLIENT_ID=${rw.clientId}\nCOFFER_CLIENT_SECRET=${rw.clientSecret}\n`, { mode: 0o600 });
	console.log(`• wrote test credentials to ${process.env.SDK_CREDENTIALS_OUT}`);
}

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
