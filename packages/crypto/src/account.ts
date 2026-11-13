// Account key material: what a client sends the server to create an account or change its password.
// Shared by the app, the installer and server-side validation.
//
//   password     --PBKDF2+HKDF--> wrapKey (wraps vault key), authKey (login proof; server keeps HMAC)
//   recovery key --HKDF--------> recovery wrapKey (wraps vault key), recovery authKey (server keeps HMAC)
//
// The recovery key is 160 random bits shown once to the user, e.g. "K7QF-2M9X-...". It is high-entropy,
// so it needs no slow KDF.

import type { Sealed } from "./aead.ts";
import { randomBytes, toB64 } from "./encoding.ts";
import { deriveKeys, deriveSubkeys, newKdfParams, type KdfParams, type Subkeys } from "./kdf.ts";
import { unwrapVaultKey, wrapVaultKey } from "./keys.ts";

export interface PasswordMaterial {
	kdf: KdfParams;
	/** base64 */
	authKey: string;
	wrappedVaultKey: Sealed;
}

export interface AccountMaterial extends PasswordMaterial {
	recoveryWrappedKey: Sealed;
	/** base64 */
	recoveryAuthKey: string;
}

// Crockford-style alphabet without I, L, O, U to avoid misreading.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RECOVERY_BYTES = 20;

function encode32(bytes: Uint8Array): string {
	let bits = 0;
	let value = 0;
	let out = "";
	for (const b of bytes) {
		value = (value << 8) | b;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out += ALPHABET[(value >>> bits) & 31];
		}
	}
	if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
	return out;
}

function decode32(s: string): Uint8Array {
	const out: number[] = [];
	let bits = 0;
	let value = 0;
	for (const c of s) {
		const v = ALPHABET.indexOf(c);
		if (v < 0) throw new Error("Invalid recovery key");
		value = (value << 5) | v;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.push((value >>> bits) & 0xff);
		}
	}
	return new Uint8Array(out);
}

export function formatRecoveryKey(bytes: Uint8Array): string {
	return encode32(bytes).match(/.{1,4}/g)!.join("-");
}

/** Accepts any case, spaces or dashes; maps easily confused letters (O→0, I/L→1). */
export function parseRecoveryKey(input: string): Uint8Array {
	const s = input.toUpperCase().replace(/[\s-]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
	if (s.length !== Math.ceil((RECOVERY_BYTES * 8) / 5)) throw new Error("Recovery key has the wrong length");
	return decode32(s).slice(0, RECOVERY_BYTES);
}

export function generateRecoveryKey(): { bytes: Uint8Array; display: string } {
	const bytes = randomBytes(RECOVERY_BYTES);
	return { bytes, display: formatRecoveryKey(bytes) };
}

export function recoverySubkeys(recoveryKey: Uint8Array): Promise<Subkeys> {
	return deriveSubkeys(recoveryKey);
}

export async function makePasswordMaterial(password: string, vaultKey: Uint8Array, iterations?: number): Promise<PasswordMaterial> {
	const kdf = newKdfParams(iterations);
	const { wrapKey, authKey } = await deriveKeys(password, kdf);
	return { kdf, authKey: toB64(authKey), wrappedVaultKey: await wrapVaultKey(wrapKey, vaultKey) };
}

/** Everything needed to create an account, plus the recovery key to show the user once. */
export async function makeAccountMaterial(
	password: string,
	vaultKey: Uint8Array,
	iterations?: number,
): Promise<{ material: AccountMaterial; recoveryKey: string }> {
	const pw = await makePasswordMaterial(password, vaultKey, iterations);
	const rk = generateRecoveryKey();
	const r = await recoverySubkeys(rk.bytes);
	const material: AccountMaterial = {
		...pw,
		recoveryWrappedKey: await wrapVaultKey(r.wrapKey, vaultKey),
		recoveryAuthKey: toB64(r.authKey),
	};
	rk.bytes.fill(0);
	return { material, recoveryKey: rk.display };
}

/** Unwrap the vault key with the recovery key. Throws DecryptError if it does not match. */
export async function unwrapWithRecovery(recoveryKey: Uint8Array, wrapped: Sealed): Promise<Uint8Array> {
	return unwrapVaultKey((await recoverySubkeys(recoveryKey)).wrapKey, wrapped);
}

