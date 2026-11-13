// RFC 4648 base32 (standard alphabet).

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOOKUP: Record<string, number> = Object.fromEntries([...ALPHABET].map((c, i) => [c, i]));

export class Base32Error extends Error {
	override name = "Base32Error";
}

/** Normalize user input: uppercase, strip whitespace, dashes and padding. */
export function normalizeBase32(input: string): string {
	return input.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
}

export function base32Decode(input: string): Uint8Array {
	const s = normalizeBase32(input);
	const out = new Uint8Array(Math.floor((s.length * 5) / 8));
	let bits = 0;
	let value = 0;
	let index = 0;
	for (const c of s) {
		const v = LOOKUP[c];
		if (v === undefined) throw new Base32Error(`Invalid base32 character: ${JSON.stringify(c)}`);
		value = (value << 5) | v;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out[index++] = (value >>> bits) & 0xff;
		}
	}
	return out;
}

export function base32Encode(bytes: Uint8Array, { padding = true }: { padding?: boolean } = {}): string {
	let out = "";
	let bits = 0;
	let value = 0;
	for (const b of bytes) {
		value = (value << 8) | b;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out += ALPHABET[(value >>> bits) & 31];
		}
	}
	if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
	if (padding) while (out.length % 8 !== 0) out += "=";
	return out;
}
