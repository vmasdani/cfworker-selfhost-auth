// Password -> root key (PBKDF2-SHA256) -> subkeys (HKDF-SHA256).
//
// The root key never leaves the client. From it we derive:
//   wrapKey: AES-256-GCM key that wraps the vault key.
//   authKey: 32 bytes sent to the server for login; the server stores only an HMAC of it.
// Knowing authKey does not reveal wrapKey.

import { importAesKey } from "./aead.ts";
import { fromB64, randomBytes, toB64, utf8 } from "./encoding.ts";

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

export interface KdfParams {
	alg: "pbkdf2-sha256";
	iterations: number;
	/** base64, 16 bytes */
	salt: string;
}

export function newKdfParams(iterations = DEFAULT_PBKDF2_ITERATIONS): KdfParams {
	return { alg: "pbkdf2-sha256", iterations, salt: toB64(randomBytes(16)) };
}

export async function deriveRootKey(secret: string, params: KdfParams): Promise<Uint8Array> {
	if (params.alg !== "pbkdf2-sha256") throw new Error(`Unsupported KDF: ${String(params.alg)}`);
	if (!Number.isInteger(params.iterations) || params.iterations < 1) throw new RangeError("Invalid iterations");
	const base = await crypto.subtle.importKey(
		"raw",
		utf8.encode(secret.normalize("NFKC")) as BufferSource,
		"PBKDF2",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", hash: "SHA-256", salt: fromB64(params.salt) as BufferSource, iterations: params.iterations },
		base,
		256,
	);
	return new Uint8Array(bits);
}

async function hkdf(root: Uint8Array, info: string): Promise<Uint8Array> {
	const base = await crypto.subtle.importKey("raw", root as BufferSource, "HKDF", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits(
		{ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: utf8.encode(info) as BufferSource },
		base,
		256,
	);
	return new Uint8Array(bits);
}

export interface Subkeys {
	wrapKey: CryptoKey;
	authKey: Uint8Array;
}

export async function deriveSubkeys(root: Uint8Array): Promise<Subkeys> {
	const [wrapRaw, authKey] = await Promise.all([hkdf(root, "cfsa/v1/wrap"), hkdf(root, "cfsa/v1/auth")]);
	const wrapKey = await importAesKey(wrapRaw);
	wrapRaw.fill(0);
	return { wrapKey, authKey };
}

export async function deriveKeys(secret: string, params: KdfParams): Promise<Subkeys> {
	const root = await deriveRootKey(secret, params);
	try {
		return await deriveSubkeys(root);
	} finally {
		root.fill(0);
	}
}
