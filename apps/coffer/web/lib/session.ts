// Account session and keys, held in memory only. Reloading the page or locking drops the keys; the
// server session cookie stays, so unlocking needs only the password (no two-step code).

import {
	DecryptError,
	deriveKeys,
	generateVaultKey,
	makeAccountMaterial,
	makePasswordMaterial,
	parseRecoveryKey,
	recoverySubkeys,
	toB64,
	unwrapVaultKey,
	unwrapWithRecovery,
	type KdfParams,
	type Sealed,
} from "@cfsa/crypto";
import { api, ApiError, type AccountResponse, type Invite, type UserSummary } from "./api.ts";
import { fingerprint, generateUserKeys, unwrapPrivateKey } from "./keys.ts";

export const MIN_PASSWORD_LENGTH = 12;

export function validatePassword(pw: string): string | null {
	if (pw.length < MIN_PASSWORD_LENGTH) return `Use at least ${MIN_PASSWORD_LENGTH} characters`;
	if (/^(.)\1+$/.test(pw)) return "Password is a single repeated character";
	return null;
}

export interface Me {
	id: string;
	username: string;
	role: "admin" | "user";
	totpEnabled: boolean;
}

export interface Unlocked {
	me: Me;
	privateKey: CryptoKey;
	publicKey: string;
	fingerprint: string;
}

let current: Unlocked | null = null;
export const sessionEvents = new EventTarget();
const emit = () => sessionEvents.dispatchEvent(new Event("change"));

export const unlocked = () => current;

export function requireUnlocked(): Unlocked {
	if (!current) throw new Error("Locked");
	return current;
}

const toMe = (r: AccountResponse): Me => ({ ...r.user, totpEnabled: r.totpEnabled });

export function setTotpEnabled(v: boolean) {
	if (current) {
		current = { ...current, me: { ...current.me, totpEnabled: v } };
		emit();
	}
}

/** The server session, if the cookie is still valid. */
export async function serverSession(): Promise<AccountResponse | null> {
	try {
		return await api<AccountResponse>("GET", "/session");
	} catch (e) {
		if (e instanceof ApiError && e.status === 401) return null;
		throw e;
	}
}

/** Load (or create, on first use) the user's key pair with the vault key, then mark the session unlocked. */
async function open(r: AccountResponse, vaultKey: Uint8Array): Promise<void> {
	try {
		let keys = await api<{ publicKey: string | null; wrappedPrivateKey?: Sealed }>("GET", "/keys");
		if (!keys.publicKey) {
			const fresh = await generateUserKeys(vaultKey, r.user.id);
			await api("PUT", "/keys", fresh).catch((e) => {
				if (!(e instanceof ApiError && e.code === "keys_exist")) throw e;
			});
			keys = await api("GET", "/keys");
		}
		const privateKey = await unwrapPrivateKey(vaultKey, r.user.id, keys.wrappedPrivateKey!);
		current = { me: toMe(r), privateKey, publicKey: keys.publicKey!, fingerprint: await fingerprint(keys.publicKey!) };
		emit();
	} finally {
		vaultKey.fill(0);
	}
}

export class TotpRequiredError extends Error {
	override name = "TotpRequiredError";
	constructor() {
		super("Enter the 6-digit code from your authenticator");
	}
}

export async function signIn(username: string, password: string, totp?: string): Promise<void> {
	const u = username.trim().toLowerCase();
	const { kdf } = await api<{ kdf: KdfParams }>("POST", "/prelogin", { username: u });
	const { wrapKey, authKey } = await deriveKeys(password, kdf);
	let r: AccountResponse;
	try {
		r = await api<AccountResponse>("POST", "/login", { username: u, authKey: toB64(authKey), ...(totp ? { totp } : {}) });
	} catch (e) {
		if (e instanceof ApiError && e.code === "totp_required") throw new TotpRequiredError();
		throw e;
	}
	await open(r, await unwrapVaultKey(wrapKey, r.wrappedVaultKey));
}

/** Unlock with the password while the server session is still valid. */
export async function unlock(r: AccountResponse, password: string): Promise<void> {
	const { wrapKey } = await deriveKeys(password, r.kdf);
	let vaultKey: Uint8Array;
	try {
		vaultKey = await unwrapVaultKey(wrapKey, r.wrappedVaultKey);
	} catch (e) {
		if (e instanceof DecryptError) throw new Error("Wrong password");
		throw e;
	}
	await open(r, vaultKey);
}

/** Returns the recovery key, which the caller must show once. */
export async function joinWithInvite(invite: string, username: string, password: string): Promise<{ recoveryKey: string; finish: () => Promise<void> }> {
	const vaultKey = generateVaultKey();
	const { material, recoveryKey } = await makeAccountMaterial(password, vaultKey);
	const r = await api<AccountResponse>("POST", "/register", { invite, username: username.trim().toLowerCase(), ...material });
	return { recoveryKey, finish: () => open(r, vaultKey) };
}

export async function recoverAccount(username: string, recoveryKey: string, newPassword: string): Promise<void> {
	const u = username.trim().toLowerCase();
	let bytes: Uint8Array;
	try {
		bytes = parseRecoveryKey(recoveryKey);
	} catch (e) {
		throw new Error(e instanceof Error ? e.message : "Invalid recovery key");
	}
	const proof = toB64((await recoverySubkeys(bytes)).authKey);
	const { recoveryWrappedKey } = await api<{ recoveryWrappedKey: Sealed }>("POST", "/recover/start", { username: u, recoveryAuthKey: proof });
	const vaultKey = await unwrapWithRecovery(bytes, recoveryWrappedKey);
	bytes.fill(0);
	const pw = await makePasswordMaterial(newPassword, vaultKey);
	const r = await api<AccountResponse>("POST", "/recover/finish", { username: u, recoveryAuthKey: proof, ...pw });
	await open(r, vaultKey);
}

export async function changePassword(currentPassword: string, next: string): Promise<void> {
	requireUnlocked();
	const r0 = await api<AccountResponse>("GET", "/session");
	const { wrapKey, authKey } = await deriveKeys(currentPassword, r0.kdf);
	let vaultKey: Uint8Array;
	try {
		vaultKey = await unwrapVaultKey(wrapKey, r0.wrappedVaultKey);
	} catch {
		throw new Error("Current password is wrong");
	}
	try {
		const pw = await makePasswordMaterial(next, vaultKey);
		await api("POST", "/account/password", { currentAuthKey: toB64(authKey), ...pw });
	} finally {
		vaultKey.fill(0);
	}
}

export const totpSetup = () => api<{ secret: string; uri: string }>("POST", "/account/totp/setup", {});

export async function totpEnable(code: string): Promise<void> {
	await api("POST", "/account/totp/enable", { code });
	setTotpEnabled(true);
}

export async function totpDisable(password: string): Promise<void> {
	const r = await api<AccountResponse>("GET", "/session");
	const { authKey } = await deriveKeys(password, r.kdf);
	await api("POST", "/account/totp/disable", { authKey: toB64(authKey) });
	setTotpEnabled(false);
}

export function lock(): void {
	current = null;
	emit();
}

export async function signOut(): Promise<void> {
	await api("POST", "/logout", {}).catch(() => {});
	lock();
}

// --- admin ---------------------------------------------------------------------------------------

export const createInvite = (role: "user" | "admin", ttlHours: number) =>
	api<{ id: string; token: string; expiresAt: number }>("POST", "/admin/invites", { role, ttlHours });
export const listInvites = () => api<{ invites: Invite[] }>("GET", "/admin/invites").then((r) => r.invites);
export const revokeInvite = (id: string) => api("DELETE", `/admin/invites/${encodeURIComponent(id)}`);
export const listUsers = () => api<{ users: UserSummary[] }>("GET", "/admin/users").then((r) => r.users);
export const checkInvite = (token: string) =>
	api<{ valid: boolean; expiresAt: number | null }>("GET", `/invites/check?token=${encodeURIComponent(token)}`);
