// Generates sdk/test-vectors.json: fixed inputs and expected outputs of the Coffer v1 client protocol, so a
// client in another language can be checked offline. Computed here with WebCrypto directly (not via the SDK);
// sdk/test/vectors.test.ts checks that sdk/coffer.ts agrees.
// Run: bun run scripts/test-vectors.ts   (output is committed; re-run only if the protocol version changes)

import { writeFileSync } from "node:fs";
import { join } from "node:path";

const te = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => Uint8Array.from(s.match(/../g)!, (h) => parseInt(h, 16));
const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");

async function hkdf(ikm: Uint8Array, info: string) {
	const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
	return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: te.encode(info) }, k, 256));
}
async function gcm(key: Uint8Array, iv: Uint8Array, data: Uint8Array, aad: string) {
	const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad) }, k, data));
}
async function hmac(key: Uint8Array, data: string) {
	const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", k, te.encode(data)));
}

const clientId = "cfi_AAECAwQFBgcICQoLDA0ODw";
const clientSecret = "cfs_EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8";
const envId = "6f1c2a4e-8b3d-4c5e-9f60-7a8b9c0d1e2f";
const envKey = unhex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
const wrapIv = unhex("000102030405060708090a0b");
const secretIv = unhex("0c0d0e0f1011121314151617");
const name = "DATABASE_URL";
const value = 'postgres://app:pä$$ "w0rd"@db.internal:5432/app\nline 2 ✓';

const authKey = await hkdf(te.encode(clientSecret), "coffer/v1/machine-auth");
const wrapKey = await hkdf(te.encode(clientSecret), "coffer/v1/machine-wrap");
const wrappedKey = { iv: b64(wrapIv), ct: b64(await gcm(wrapKey, wrapIv, envKey, `coffer/v1/machine-key/${clientId}`)) };
const encKey = await hkdf(envKey, "coffer/v1/secret-enc");
const indexKey = await hkdf(envKey, "coffer/v1/secret-index");
const mac = hex(await hmac(indexKey, name));
const plaintext = JSON.stringify({ name, value });
const secret = { mac, iv: b64(secretIv), ct: b64(await gcm(encKey, secretIv, te.encode(plaintext), `coffer/v1/secret/${envId}/${mac}`)) };

const vectors = {
	description:
		"Coffer v1 client protocol test vectors. HKDF = HKDF-SHA256, 32 zero-byte salt, 32-byte output. " +
		"Hex values are lowercase; base64 is standard with padding; ct = ciphertext || 16-byte GCM tag.",
	input: { clientId, clientSecret, envId, envKeyHex: hex(envKey), name, value, wrapIvB64: b64(wrapIv), secretIvB64: b64(secretIv) },
	expected: {
		authKeyB64: b64(authKey),
		authorizationHeader: `Bearer ${clientId}.${b64(authKey)}`,
		wrapKeyHex: hex(wrapKey),
		wrappedKey,
		encKeyHex: hex(encKey),
		indexKeyHex: hex(indexKey),
		mac,
		plaintextJson: plaintext,
		secret,
	},
	notes: [
		"GET /api/v1/identity would return { envId, wrappedKey } with these values; decrypting wrappedKey with wrapKey and AAD 'coffer/v1/machine-key/<clientId>' must give envKeyHex.",
		"GET /api/v1/secrets would return { secrets: [secret] }; decrypting it must give plaintextJson, whose name hashes to mac.",
		"Encryption uses a random IV in real use. To compare ciphertext byte for byte, encrypt plaintextJson with the fixed secretIv; JSON from your language may escape differently, which is fine as long as other clients decode it.",
	],
};

writeFileSync(join(import.meta.dir, "..", "sdk", "test-vectors.json"), JSON.stringify(vectors, null, "\t") + "\n");
console.log("wrote sdk/test-vectors.json");
