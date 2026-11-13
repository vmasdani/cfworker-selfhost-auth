// Cache of non-extractable HMAC keys per entry, cleared on lock.

import { base32Decode, hotp, importOtpKey, totpCounter } from "@cfsa/totp";
import type { Entry } from "./entries.ts";

const cache = new Map<string, Promise<CryptoKey>>();

function keyFor(e: Entry): Promise<CryptoKey> {
	const id = `${e.id}:${e.algorithm}:${e.secret}`;
	let k = cache.get(id);
	if (!k) {
		k = importOtpKey(base32Decode(e.secret), e.algorithm);
		cache.set(id, k);
	}
	return k;
}

export function clearOtpKeys(): void {
	cache.clear();
}

export function entryCounter(e: Entry, nowMs: number): number {
	return e.type === "totp" ? totpCounter(nowMs, e.period) : e.counter;
}

export async function codeFor(e: Entry, counter: number): Promise<string> {
	return hotp(await keyFor(e), counter, e.digits);
}

/** "123456" -> "123 456", "12345678" -> "1234 5678". */
export function formatCode(code: string): string {
	const n = code.length;
	const size = n % 3 === 0 ? 3 : n % 4 === 0 ? 4 : Math.ceil(n / 2);
	return code.replace(new RegExp(`(.{${size}})(?=.)`, "g"), "$1 ");
}
