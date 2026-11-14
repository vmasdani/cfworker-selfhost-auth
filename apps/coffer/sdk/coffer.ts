// Coffer client: one file, no dependencies. Node.js 20+, Bun, Deno, Cloudflare Workers, browsers.
// Plain TypeScript (no enums or parameter properties), so Node's type stripping can run it as is.
// Secrets are encrypted and decrypted here; the Coffer server only ever sees ciphertext.
//
//   COFFER_URL=__COFFER_URL__        (optional; defaults to the URL below)
//   COFFER_CLIENT_ID=cfi_...
//   COFFER_CLIENT_SECRET=cfs_...
//
//   import { Coffer } from "./coffer.ts";
//   const coffer = Coffer.fromEnv();
//   const all = await coffer.listAllSecrets();          // { DATABASE_URL: "...", ... }
//   const db = await coffer.getSecret("DATABASE_URL");  // string | undefined
//   await coffer.writeSecret("API_TOKEN", "s3cr3t");     // needs a read-write client ID
//   await coffer.deleteSecret("API_TOKEN");
//
// Protocol (Coffer v1). HKDF is HKDF-SHA256 with a 32-byte zero salt and 32-byte output.
//   authKey  = HKDF(utf8(clientSecret), "coffer/v1/machine-auth")   sent as "Bearer <clientId>.<base64 authKey>"
//   wrapKey  = HKDF(utf8(clientSecret), "coffer/v1/machine-wrap")
//   envKey   = AES-256-GCM-open(wrapKey, identity.wrappedKey, aad "coffer/v1/machine-key/<clientId>")
//   encKey   = HKDF(envKey, "coffer/v1/secret-enc");  indexKey = HKDF(envKey, "coffer/v1/secret-index")
//   mac      = hex(HMAC-SHA256(indexKey, utf8(name)))
//   secret   = AES-256-GCM(encKey, utf8(JSON {"name","value"}), aad "coffer/v1/secret/<envId>/<mac>")
//   {iv, ct} are base64; ct is ciphertext followed by the 16-byte tag.

const DEFAULT_URL = "__COFFER_URL__";

type Sealed = { iv: string; ct: string };
type SecretRow = Sealed & { mac: string; version: number; updatedAt: number };
type Identity = { clientId: string; scope: "read" | "write"; project: string; environment: string; envId: string; wrappedKey: Sealed };
type Keys = { identity: Identity; enc: CryptoKey; index: CryptoKey };

export class CofferError extends Error {
	readonly status: number;
	readonly code: string;
	constructor(status: number, code: string, message: string) {
		super(message);
		this.name = "CofferError";
		this.status = status;
		this.code = code;
	}
}

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = globalThis.crypto.subtle;

const toB64 = (b: Uint8Array) => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function hkdf(ikm: BufferSource, info: string) {
	const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
	return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: te.encode(info) }, base, 256));
}

const aesKey = (raw: BufferSource) => subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

async function open(key: CryptoKey, s: Sealed, aad: string) {
	return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: fromB64(s.iv), additionalData: te.encode(aad) }, key, fromB64(s.ct)));
}

async function seal(key: CryptoKey, data: BufferSource, aad: string): Promise<Sealed> {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad) }, key, data));
	return { iv: toB64(iv), ct: toB64(ct) };
}

function readEnv(name: string): string | undefined {
	const g = globalThis as { process?: { env: Record<string, string | undefined> }; Deno?: { env: { get(k: string): string | undefined } } };
	return g.process?.env?.[name] ?? g.Deno?.env.get(name);
}

export class Coffer {
	private readonly url: string;
	private readonly clientId: string;
	private readonly clientSecret: string;
	private keys?: Promise<Keys>;
	private auth?: Promise<string>;

	constructor(url: string, clientId: string, clientSecret: string) {
		if (!/^cfi_[A-Za-z0-9_-]{22}$/.test(clientId)) throw new Error("Coffer: invalid client ID");
		if (!clientSecret.startsWith("cfs_")) throw new Error("Coffer: invalid client secret");
		this.url = url.replace(/\/+$/, "");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	/** Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET and optionally COFFER_URL. Pass `env` on Cloudflare Workers. */
	static fromEnv(env?: Record<string, unknown>): Coffer {
		const get = (k: string) => (env ? (env[k] as string | undefined) : readEnv(k));
		const id = get("COFFER_CLIENT_ID");
		const secret = get("COFFER_CLIENT_SECRET");
		if (!id || !secret) throw new Error("Coffer: set COFFER_CLIENT_ID and COFFER_CLIENT_SECRET");
		return new Coffer(get("COFFER_URL") || DEFAULT_URL, id, secret);
	}

	/** All secrets of this client's environment, by name. */
	async listAllSecrets(): Promise<Record<string, string>> {
		const k = await this.load();
		const { secrets } = await this.request<{ secrets: SecretRow[] }>("GET", "/secrets");
		const out: Record<string, string> = {};
		for (const row of secrets) {
			const s = await this.decrypt(k, row);
			out[s.name] = s.value;
		}
		return out;
	}

	/** One secret's value, or undefined if it does not exist. */
	async getSecret(name: string): Promise<string | undefined> {
		const k = await this.load();
		const mac = await this.mac(k, name);
		try {
			return (await this.decrypt(k, await this.request<SecretRow>("GET", `/secrets/${mac}`))).value;
		} catch (e) {
			if (e instanceof CofferError && e.status === 404) return undefined;
			throw e;
		}
	}

	/** Create or replace a secret. Returns its new version number. */
	async writeSecret(name: string, value: string): Promise<number> {
		if (!name) throw new Error("Coffer: empty secret name");
		const k = await this.load();
		const mac = await this.mac(k, name);
		const sealed = await seal(k.enc, te.encode(JSON.stringify({ name, value })), `coffer/v1/secret/${k.identity.envId}/${mac}`);
		return (await this.request<SecretRow>("PUT", `/secrets/${mac}`, sealed)).version;
	}

	/** Returns false if the secret did not exist. */
	async deleteSecret(name: string): Promise<boolean> {
		const k = await this.load();
		return (await this.request<{ deleted: boolean }>("DELETE", `/secrets/${await this.mac(k, name)}`)).deleted;
	}

	/** Project, environment and scope of this client ID. */
	async identity(): Promise<Omit<Identity, "wrappedKey">> {
		const { wrappedKey: _, ...rest } = (await this.load()).identity;
		return rest;
	}

	private async mac(k: Keys, name: string): Promise<string> {
		return hex(new Uint8Array(await subtle.sign("HMAC", k.index, te.encode(name))));
	}

	private async decrypt(k: Keys, row: SecretRow): Promise<{ name: string; value: string }> {
		const s = JSON.parse(td.decode(await open(k.enc, row, `coffer/v1/secret/${k.identity.envId}/${row.mac}`))) as { name: string; value: string };
		if ((await this.mac(k, s.name)) !== row.mac) throw new Error("Coffer: secret name does not match its index");
		return s;
	}

	private load(): Promise<Keys> {
		this.keys ??= (async () => {
			const identity = await this.request<Identity>("GET", "/identity");
			const wrap = await aesKey(await hkdf(te.encode(this.clientSecret), "coffer/v1/machine-wrap"));
			const envKey = await open(wrap, identity.wrappedKey, `coffer/v1/machine-key/${this.clientId}`);
			const enc = await aesKey(await hkdf(envKey, "coffer/v1/secret-enc"));
			const index = await subtle.importKey("raw", await hkdf(envKey, "coffer/v1/secret-index"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
			envKey.fill(0);
			return { identity, enc, index };
		})();
		this.keys.catch(() => (this.keys = undefined));
		return this.keys;
	}

	private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
		this.auth ??= hkdf(te.encode(this.clientSecret), "coffer/v1/machine-auth").then((k) => `Bearer ${this.clientId}.${toB64(k)}`);
		const res = await fetch(`${this.url}/api/v1${path}`, {
			method,
			headers: { Authorization: await this.auth, ...(body ? { "Content-Type": "application/json" } : {}) },
			body: body ? JSON.stringify(body) : undefined,
		});
		const data = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
		if (!res.ok) throw new CofferError(res.status, data.error ?? "http_error", `Coffer: ${data.message ?? data.error ?? res.statusText} (${res.status})`);
		return data as T;
	}
}
