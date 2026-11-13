// HOTP (RFC 4226) and TOTP (RFC 6238) on WebCrypto.

export type OtpAlgorithm = "SHA1" | "SHA256" | "SHA512";

const HASH: Record<OtpAlgorithm, string> = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

export function importOtpKey(secret: Uint8Array, algorithm: OtpAlgorithm = "SHA1"): Promise<CryptoKey> {
	if (secret.length === 0) throw new RangeError("OTP secret is empty");
	return crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: HASH[algorithm] }, false, ["sign"]);
}

export async function hotp(key: CryptoKey, counter: number, digits = 6): Promise<string> {
	if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError("Invalid HOTP counter");
	const msg = new ArrayBuffer(8);
	const view = new DataView(msg);
	view.setUint32(0, Math.floor(counter / 2 ** 32));
	view.setUint32(4, counter >>> 0);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
	const offset = mac[mac.length - 1]! & 0x0f;
	const bin =
		((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
	return (bin % 10 ** digits).toString().padStart(digits, "0");
}

/** TOTP time step for a Unix time in milliseconds. */
export function totpCounter(timeMs: number, period = 30): number {
	return Math.floor(timeMs / 1000 / period);
}

/** Milliseconds remaining in the current TOTP period. */
export function totpRemainingMs(timeMs: number, period = 30): number {
	const periodMs = period * 1000;
	return periodMs - (timeMs % periodMs);
}

export function totp(key: CryptoKey, timeMs: number, { period = 30, digits = 6 } = {}): Promise<string> {
	return hotp(key, totpCounter(timeMs, period), digits);
}
