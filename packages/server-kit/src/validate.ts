// Small runtime validators for request bodies (no dependency).

import type { AccountMaterial, KdfParams, PasswordMaterial, Sealed } from "@cfsa/crypto";

export class HttpError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message?: string,
		readonly extra?: Record<string, unknown>,
	) {
		super(message ?? code);
	}
}

export const bad = (code: string, message?: string) => new HttpError(400, code, message);

type Obj = Record<string, unknown>;

export function obj(v: unknown, what = "body"): Obj {
	if (typeof v !== "object" || v === null || Array.isArray(v)) throw bad("invalid_request", `${what} must be an object`);
	return v as Obj;
}

export function str(o: Obj, k: string, { max = 1024, min = 0 } = {}): string {
	const v = o[k];
	if (typeof v !== "string" || v.length < min || v.length > max) throw bad("invalid_request", `${k} must be a string`);
	return v;
}

export function optStr(o: Obj, k: string, opts?: { max?: number }): string | undefined {
	return o[k] === undefined || o[k] === null ? undefined : str(o, k, opts);
}

export function int(o: Obj, k: string, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}): number {
	const v = o[k];
	if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) throw bad("invalid_request", `${k} must be an integer`);
	return v;
}

export function bool(o: Obj, k: string): boolean {
	if (typeof o[k] !== "boolean") throw bad("invalid_request", `${k} must be a boolean`);
	return o[k] as boolean;
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

export function b64(o: Obj, k: string, { bytes, max = 65536 }: { bytes?: number; max?: number } = {}): string {
	const v = str(o, k, { max });
	if (!B64.test(v) || v.length % 4 !== 0) throw bad("invalid_request", `${k} must be base64`);
	if (bytes !== undefined && Math.floor((v.length * 3) / 4) - (v.match(/=+$/)?.[0].length ?? 0) !== bytes) {
		throw bad("invalid_request", `${k} must be ${bytes} bytes`);
	}
	return v;
}

export function sealed(o: Obj, k: string, { max = 65536, allowEmpty = false } = {}): Sealed {
	const s = obj(o[k], k);
	const iv = allowEmpty && s.iv === "" ? "" : b64(s, "iv", { bytes: 12 });
	const ct = allowEmpty && s.ct === "" ? "" : b64(s, "ct", { max });
	return { iv, ct };
}

export const MIN_KDF_ITERATIONS = 100_000;
export const MAX_KDF_ITERATIONS = 10_000_000;

export function kdf(o: Obj, k = "kdf"): KdfParams {
	const p = obj(o[k], k);
	if (p.alg !== "pbkdf2-sha256") throw bad("invalid_request", "Unsupported KDF");
	return {
		alg: "pbkdf2-sha256",
		iterations: int(p, "iterations", { min: MIN_KDF_ITERATIONS, max: MAX_KDF_ITERATIONS }),
		salt: b64(p, "salt", { bytes: 16 }),
	};
}

export function passwordMaterial(o: Obj): PasswordMaterial {
	return { kdf: kdf(o), authKey: b64(o, "authKey", { bytes: 32 }), wrappedVaultKey: sealed(o, "wrappedVaultKey", { max: 256 }) };
}

export function accountMaterial(o: Obj): AccountMaterial {
	return {
		...passwordMaterial(o),
		recoveryWrappedKey: sealed(o, "recoveryWrappedKey", { max: 256 }),
		recoveryAuthKey: b64(o, "recoveryAuthKey", { bytes: 32 }),
	};
}

const USERNAME = /^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])$/;

export function normalizeUsername(v: string): string {
	return v.trim().toLowerCase();
}

export function username(o: Obj, k = "username"): string {
	const u = normalizeUsername(str(o, k, { max: 64 }));
	if (!USERNAME.test(u)) throw bad("invalid_username", "Username: 3–64 characters, a–z, 0–9, '.', '_' or '-'");
	return u;
}

/** Constant-time string comparison (hashes both sides first so lengths do not leak). */
export async function timingSafeEqualStrings(a: string, b: string): Promise<boolean> {
	const enc = new TextEncoder();
	const [ha, hb] = await Promise.all([
		crypto.subtle.digest("SHA-256", enc.encode(a)),
		crypto.subtle.digest("SHA-256", enc.encode(b)),
	]);
	const x = new Uint8Array(ha);
	const y = new Uint8Array(hb);
	let d = 0;
	for (let i = 0; i < x.length; i++) d |= x[i]! ^ y[i]!;
	return d === 0;
}
