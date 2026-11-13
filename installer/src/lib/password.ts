export const MIN_MASTER_PASSWORD_LENGTH = 12;

/** Returns an error message, or null when the master password is acceptable. */
export function validateMasterPassword(password: string, login: string): string | null {
	if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
		return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters. A passphrase of 4+ words is easy to remember and strong.`;
	}
	if (/^(.)\1+$/u.test(password)) return "Password is a single repeated character.";
	if (password.trim() !== password) return "Password starts or ends with a space; that is easy to get wrong when typing.";
	const local = login.split("@")[0]!.toLowerCase();
	if (local.length >= 3 && password.toLowerCase().includes(local)) return "Password must not contain your login name.";
	return null;
}

export function generateSecret(bytes = 32): string {
	return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64");
}
