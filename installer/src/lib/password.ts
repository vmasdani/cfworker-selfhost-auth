const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; // no 0/O, 1/l/I

/** Uniform random index in [0, n) via rejection sampling. */
function randomIndex(n: number): number {
	const limit = 256 - (256 % n);
	const buf = new Uint8Array(1);
	for (;;) {
		crypto.getRandomValues(buf);
		if (buf[0]! < limit) return buf[0]! % n;
	}
}

/**
 * Generated master password: `groups` groups of `size` unambiguous characters joined by "-".
 * Default 5x6 = 30 characters, about 175 bits of entropy.
 */
export function generatePassword(groups = 5, size = 6): string {
	return Array.from({ length: groups }, () =>
		Array.from({ length: size }, () => ALPHABET[randomIndex(ALPHABET.length)]).join(""),
	).join("-");
}

export function generateSecret(bytes = 32): string {
	return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64");
}
