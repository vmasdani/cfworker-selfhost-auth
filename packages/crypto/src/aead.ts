// AES-256-GCM sealing with optional associated data.

import { fromB64, randomBytes, toB64, utf8 } from "./encoding.ts";

/** Ciphertext envelope. `iv` and `ct` are base64. */
export interface Sealed {
	iv: string;
	ct: string;
}

export class DecryptError extends Error {
	override name = "DecryptError";
	constructor() {
		super("Decryption failed: wrong key or corrupted data");
	}
}

export function importAesKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
	if (raw.length !== 32) throw new RangeError("AES key must be 32 bytes");
	return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", extractable, ["encrypt", "decrypt"]);
}

function params(iv: Uint8Array, aad?: string): { name: "AES-GCM"; iv: BufferSource; additionalData?: BufferSource } {
	return aad === undefined
		? { name: "AES-GCM", iv: iv as BufferSource }
		: { name: "AES-GCM", iv: iv as BufferSource, additionalData: utf8.encode(aad) as BufferSource };
}

export async function seal(key: CryptoKey, plaintext: Uint8Array, aad?: string): Promise<Sealed> {
	const iv = randomBytes(12);
	const ct = new Uint8Array(await crypto.subtle.encrypt(params(iv, aad), key, plaintext as BufferSource));
	return { iv: toB64(iv), ct: toB64(ct) };
}

export async function open(key: CryptoKey, sealed: Sealed, aad?: string): Promise<Uint8Array> {
	try {
		const pt = await crypto.subtle.decrypt(params(fromB64(sealed.iv), aad), key, fromB64(sealed.ct) as BufferSource);
		return new Uint8Array(pt);
	} catch {
		throw new DecryptError();
	}
}

export async function sealJSON(key: CryptoKey, value: unknown, aad?: string): Promise<Sealed> {
	return seal(key, utf8.encode(JSON.stringify(value)), aad);
}

export async function openJSON<T>(key: CryptoKey, sealed: Sealed, aad?: string): Promise<T> {
	return JSON.parse(utf8.decode(await open(key, sealed, aad))) as T;
}
