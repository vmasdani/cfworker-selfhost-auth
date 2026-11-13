// Pure vault key hierarchy logic (no storage, no DOM). Tested with bun.
//
//   master password --PBKDF2/HKDF--> wrapKey --wraps--> vault key (random 256-bit)
//   PIN (optional)  --PBKDF2/HKDF--> pinKey  --wraps--> same vault key (local only)
//   vault key --AES-256-GCM--> each entry

import {
	DEFAULT_PBKDF2_ITERATIONS,
	deriveKeys,
	generateVaultKey,
	newKdfParams,
	unwrapVaultKey,
	wrapVaultKey,
	type KdfParams,
	type Sealed,
} from "@cfsa/crypto";

export const MIN_PASSWORD_LENGTH = 12;
export const MIN_PIN_LENGTH = 8;
export const MAX_PIN_FAILURES = 5;

export interface PinWrap {
	kdf: KdfParams;
	wrapped: Sealed;
	failures: number;
}

export interface VaultHeader {
	v: 1;
	kdf: KdfParams;
	wrapped: Sealed;
	pin?: PinWrap;
	createdAt: number;
}

export function validatePassword(pw: string): string | null {
	if (pw.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters`;
	if (/^(.)\1+$/.test(pw)) return "Password is a single repeated character";
	return null;
}

export function validatePin(pin: string): string | null {
	if (!/^\d+$/.test(pin)) return "PIN must contain digits only";
	if (pin.length < MIN_PIN_LENGTH) return `PIN must be at least ${MIN_PIN_LENGTH} digits`;
	if (/^(\d)\1+$/.test(pin)) return "PIN is a single repeated digit";
	if ("01234567890123456789".includes(pin) || "98765432109876543210".includes(pin)) return "PIN is a simple sequence";
	return null;
}

export async function wrapWithSecret(
	secret: string,
	vaultKey: Uint8Array,
	iterations = DEFAULT_PBKDF2_ITERATIONS,
): Promise<{ kdf: KdfParams; wrapped: Sealed }> {
	const kdf = newKdfParams(iterations);
	const { wrapKey } = await deriveKeys(secret, kdf);
	return { kdf, wrapped: await wrapVaultKey(wrapKey, vaultKey) };
}

/** Throws DecryptError on a wrong secret. */
export async function unwrapWithSecret(secret: string, kdf: KdfParams, wrapped: Sealed): Promise<Uint8Array> {
	const { wrapKey } = await deriveKeys(secret, kdf);
	return unwrapVaultKey(wrapKey, wrapped);
}

export async function createHeader(
	password: string,
	pin?: string,
	iterations = DEFAULT_PBKDF2_ITERATIONS,
): Promise<{ header: VaultHeader; vaultKey: Uint8Array }> {
	const pwErr = validatePassword(password);
	if (pwErr) throw new Error(pwErr);
	if (pin !== undefined) {
		const pinErr = validatePin(pin);
		if (pinErr) throw new Error(pinErr);
	}
	const vaultKey = generateVaultKey();
	const main = await wrapWithSecret(password, vaultKey, iterations);
	const header: VaultHeader = { v: 1, ...main, createdAt: Date.now() };
	if (pin !== undefined) header.pin = { ...(await wrapWithSecret(pin, vaultKey, iterations)), failures: 0 };
	return { header, vaultKey };
}
