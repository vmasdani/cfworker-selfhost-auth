export const utf8 = {
	encode: (s: string): Uint8Array => new TextEncoder().encode(s),
	decode: (b: Uint8Array): string => new TextDecoder().decode(b),
};

export function toB64(bytes: Uint8Array): string {
	let s = "";
	for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	return btoa(s);
}

export function fromB64(b64: string): Uint8Array {
	const s = atob(b64);
	const out = new Uint8Array(s.length);
	for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
	return out;
}

export function randomBytes(n: number): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(n));
}

/** Constant-time comparison of equal-length byte arrays. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

export function toB64Url(bytes: Uint8Array): string {
	return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(s: string): Uint8Array {
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
	return fromB64(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}
