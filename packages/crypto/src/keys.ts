// Vault key generation and wrapping.

import { open, seal, type Sealed } from "./aead.ts";
import { randomBytes } from "./encoding.ts";

const VAULT_KEY_AAD = "cfsa/v1/vault-key";

export function generateVaultKey(): Uint8Array {
	return randomBytes(32);
}

export function wrapVaultKey(wrapKey: CryptoKey, vaultKey: Uint8Array): Promise<Sealed> {
	return seal(wrapKey, vaultKey, VAULT_KEY_AAD);
}

/** Throws DecryptError when wrapKey is wrong. */
export async function unwrapVaultKey(wrapKey: CryptoKey, wrapped: Sealed): Promise<Uint8Array> {
	const raw = await open(wrapKey, wrapped, VAULT_KEY_AAD);
	if (raw.length !== 32) throw new RangeError("Unwrapped vault key has wrong length");
	return raw;
}
