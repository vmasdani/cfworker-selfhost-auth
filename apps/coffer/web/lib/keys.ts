// Coffer key hierarchy (client side). The server stores only what these functions output.
//
//   vault key (from the account, see @cfsa/crypto)
//     └─ seals the user's ECDH P-256 private key
//   project key (random 32 bytes)
//     ├─ wrapped to each member's public key: ephemeral ECDH → HKDF → AES-256-GCM
//     └─ seals each environment key
//   environment key (random 32 bytes)
//     ├─ secret-enc and secret-index subkeys (HKDF) encrypt and address secrets
//     └─ sealed for each machine identity with HKDF(client secret, "coffer/v1/machine-wrap")
//
// Must match sdk/coffer.ts byte for byte (secret format, HKDF info strings, AAD strings).

import { fromB64, hkdf, importAesKey, open, randomBytes, seal, toB64, toB64Url, utf8, type Sealed } from "@cfsa/crypto";

export const AAD = {
	privateKey: (userId: string) => `coffer/v1/user-private-key/${userId}`,
	projectKey: (projectId: string, userId: string) => `coffer/v1/project-key/${projectId}/${userId}`,
	envKey: (envId: string) => `coffer/v1/env-key/${envId}`,
	machineKey: (clientId: string) => `coffer/v1/machine-key/${clientId}`,
	secret: (envId: string, mac: string) => `coffer/v1/secret/${envId}/${mac}`,
};

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const buf = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;

export type MemberWrapped = Sealed & { epk: string };

// --- user key pair ------------------------------------------------------------------------------------

export async function generateUserKeys(vaultKey: Uint8Array, userId: string): Promise<{ publicKey: string; wrappedPrivateKey: Sealed }> {
	const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
	const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
	try {
		const wrappedPrivateKey = await seal(await importAesKey(vaultKey), pkcs8, AAD.privateKey(userId));
		return { publicKey: toB64(spki), wrappedPrivateKey };
	} finally {
		pkcs8.fill(0);
	}
}

export async function unwrapPrivateKey(vaultKey: Uint8Array, userId: string, wrapped: Sealed): Promise<CryptoKey> {
	const pkcs8 = await open(await importAesKey(vaultKey), wrapped, AAD.privateKey(userId));
	try {
		return await crypto.subtle.importKey("pkcs8", buf(pkcs8), ECDH, false, ["deriveBits"]);
	} finally {
		pkcs8.fill(0);
	}
}

async function memberWrapKey(priv: CryptoKey, pub: CryptoKey, projectId: string, userId: string): Promise<CryptoKey> {
	const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256));
	try {
		return await importAesKey(await hkdf(shared, `coffer/v1/member-wrap/${projectId}/${userId}`));
	} finally {
		shared.fill(0);
	}
}

/** Wrap a project key to a member's public key (SPKI, base64). */
export async function wrapForMember(projectKey: Uint8Array, publicKeyB64: string, projectId: string, userId: string): Promise<MemberWrapped> {
	const pub = await crypto.subtle.importKey("spki", buf(fromB64(publicKeyB64)), ECDH, false, []);
	const eph = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
	const key = await memberWrapKey(eph.privateKey, pub, projectId, userId);
	const epk = toB64(new Uint8Array(await crypto.subtle.exportKey("spki", eph.publicKey)));
	return { epk, ...(await seal(key, projectKey, AAD.projectKey(projectId, userId))) };
}

export async function unwrapMemberKey(privateKey: CryptoKey, w: MemberWrapped, projectId: string, userId: string): Promise<Uint8Array> {
	const epk = await crypto.subtle.importKey("spki", buf(fromB64(w.epk)), ECDH, false, []);
	const key = await memberWrapKey(privateKey, epk, projectId, userId);
	return open(key, w, AAD.projectKey(projectId, userId));
}

/** Short fingerprint of a public key, for comparing out of band. */
export async function fingerprint(publicKeyB64: string): Promise<string> {
	const h = new Uint8Array(await crypto.subtle.digest("SHA-256", buf(fromB64(publicKeyB64))));
	return Array.from(h.slice(0, 10), (b) => b.toString(16).padStart(2, "0")).join("").match(/.{4}/g)!.join(" ");
}

// --- project and environment keys ---------------------------------------------------------------------

export const newKey = () => randomBytes(32);

export async function wrapEnvKey(projectKey: Uint8Array, envKey: Uint8Array, envId: string): Promise<Sealed> {
	return seal(await importAesKey(projectKey), envKey, AAD.envKey(envId));
}

export async function unwrapEnvKey(projectKey: Uint8Array, wrapped: Sealed, envId: string): Promise<Uint8Array> {
	return open(await importAesKey(projectKey), wrapped, AAD.envKey(envId));
}

// --- secrets ------------------------------------------------------------------------------------------

export interface EnvCrypto {
	envId: string;
	mac(name: string): Promise<string>;
	seal(name: string, value: string): Promise<{ mac: string } & Sealed>;
	open(row: { mac: string } & Sealed): Promise<{ name: string; value: string }>;
}

export async function envCrypto(envId: string, envKey: Uint8Array): Promise<EnvCrypto> {
	const enc = await importAesKey(await hkdf(envKey, "coffer/v1/secret-enc"));
	const index = await crypto.subtle.importKey("raw", buf(await hkdf(envKey, "coffer/v1/secret-index")), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const mac = async (name: string) =>
		Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", index, buf(utf8.encode(name)))), (b) => b.toString(16).padStart(2, "0")).join("");
	return {
		envId,
		mac,
		async seal(name, value) {
			const m = await mac(name);
			return { mac: m, ...(await seal(enc, utf8.encode(JSON.stringify({ name, value })), AAD.secret(envId, m))) };
		},
		async open(row) {
			const s = JSON.parse(utf8.decode(await open(enc, row, AAD.secret(envId, row.mac)))) as { name: string; value: string };
			if ((await mac(s.name)) !== row.mac) throw new Error("Secret name does not match its index");
			return s;
		},
	};
}

// --- machine identities -------------------------------------------------------------------------------

export interface MachineCredentials {
	clientId: string;
	clientSecret: string;
	/** For the server: base64 auth key and the sealed environment key. */
	authKey: string;
	wrappedKey: Sealed;
}

export async function newMachineCredentials(envKey: Uint8Array): Promise<MachineCredentials> {
	const clientId = `cfi_${toB64Url(randomBytes(16))}`;
	const clientSecret = `cfs_${toB64Url(randomBytes(32))}`;
	const ikm = utf8.encode(clientSecret);
	const [authKey, wrapRaw] = await Promise.all([hkdf(ikm, "coffer/v1/machine-auth"), hkdf(ikm, "coffer/v1/machine-wrap")]);
	const wrappedKey = await seal(await importAesKey(wrapRaw), envKey, AAD.machineKey(clientId));
	wrapRaw.fill(0);
	return { clientId, clientSecret, authKey: toB64(authKey), wrappedKey };
}
