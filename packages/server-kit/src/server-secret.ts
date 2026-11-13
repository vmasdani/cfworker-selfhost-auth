// Keys derived from the Worker's SERVER_SECRET. Each purpose gets its own HKDF subkey.

import { fromB64, hkdf, importAesKey, open, seal, timingSafeEqual, toB64, utf8, type Sealed } from "@cfsa/crypto";

export interface ServerKeys {
	/** HMAC of a client auth key; what the database stores instead of the key. */
	verifier(authKeyB64: string): Promise<string>;
	verify(authKeyB64: string, stored: string): Promise<boolean>;
	/** Deterministic fake salt for unknown usernames, so pre-login does not reveal which exist. */
	decoySalt(username: string): Promise<string>;
	sealSecret(plaintext: string, aad: string): Promise<Sealed>;
	openSecret(sealed: Sealed, aad: string): Promise<string>;
}

async function hmacKey(raw: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmac(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, data as BufferSource));
}

const cache = new Map<string, Promise<ServerKeys>>();

export function serverKeys(serverSecret: string | undefined): Promise<ServerKeys> {
	if (!serverSecret || serverSecret.length < 32) throw new Error("SERVER_SECRET is missing or shorter than 32 characters");
	let p = cache.get(serverSecret);
	if (!p) {
		p = build(serverSecret);
		cache.set(serverSecret, p);
	}
	return p;
}

async function build(secret: string): Promise<ServerKeys> {
	const ikm = utf8.encode(secret);
	const [verifierKey, decoyKey, sealKey] = await Promise.all([
		hkdf(ikm, "cfsa/server/v1/auth-verifier").then(hmacKey),
		hkdf(ikm, "cfsa/server/v1/decoy-salt").then(hmacKey),
		hkdf(ikm, "cfsa/server/v1/seal").then((raw) => importAesKey(raw)),
	]);
	const verifier = async (authKeyB64: string) => toB64(await hmac(verifierKey, fromB64(authKeyB64)));
	return {
		verifier,
		async verify(authKeyB64, stored) {
			return timingSafeEqual(fromB64(await verifier(authKeyB64)), fromB64(stored));
		},
		async decoySalt(username) {
			return toB64((await hmac(decoyKey, utf8.encode(username))).slice(0, 16));
		},
		sealSecret: (plaintext, aad) => seal(sealKey, utf8.encode(plaintext), aad),
		openSecret: async (sealed, aad) => utf8.decode(await open(sealKey, sealed, aad)),
	};
}
