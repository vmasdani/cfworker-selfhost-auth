// Sync account: sign in, join with an invite, recover, and encrypted sync.
//
// The device keeps working offline. Linking changes only which password unwraps the local vault:
// after linking, the account password is the master password on this device.

import {
	DecryptError,
	deriveKeys,
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
import { api, ApiError, type AccountResponse, type Invite, type RemoteRecord } from "./api.ts";
import type { EntryRecord } from "./entries.ts";
import { meta, records } from "./idb.ts";
import { validatePassword } from "./vault-core.ts";
import * as vault from "./vault.ts";

export interface AccountInfo {
	userId: string;
	username: string;
	role: "admin" | "user";
	totpEnabled: boolean;
}

export interface SyncState {
	cursor: number;
	lastSyncAt: number | null;
	/** "signed_out" when the server session is gone and the user must sign in again. */
	status: "ok" | "error" | "signed_out" | "offline";
	message?: string;
}

const EMPTY_SYNC: SyncState = { cursor: 0, lastSyncAt: null, status: "ok" };

export const getAccount = () => meta.get<AccountInfo>("account");
export const getSyncState = async () => ({ ...EMPTY_SYNC, ...(await meta.get<SyncState>("sync")) });
const setSyncState = async (s: Partial<SyncState>) => meta.put("sync", { ...(await getSyncState()), ...s });

export const syncEvents = new EventTarget();
const emit = () => syncEvents.dispatchEvent(new Event("state"));

function saveAccount(r: AccountResponse) {
	return meta.put("account", { userId: r.user.id, username: r.user.username, role: r.user.role, totpEnabled: r.totpEnabled } satisfies AccountInfo);
}

// --- sign in -------------------------------------------------------------------------------

export class TotpRequiredError extends Error {
	override name = "TotpRequiredError";
	constructor() {
		super("Enter the 6-digit code from your authenticator");
	}
}

async function passwordLogin(username: string, password: string, totp?: string) {
	const { kdf } = await api<{ kdf: KdfParams }>("POST", "/prelogin", { username });
	const { wrapKey, authKey } = await deriveKeys(password, kdf);
	try {
		const r = await api<AccountResponse>("POST", "/login", { username, authKey: toB64(authKey), ...(totp ? { totp } : {}) });
		return { r, raw: await unwrapVaultKey(wrapKey, r.wrappedVaultKey) };
	} catch (e) {
		if (e instanceof ApiError && e.code === "totp_required") throw new TotpRequiredError();
		throw e;
	}
}

/** Point the local vault at an account. Covers new devices, first link and re-sign-in. */
async function linkLocal(r: AccountResponse, raw: Uint8Array) {
	const current = await getAccount();
	if (current && current.userId !== r.user.id) {
		throw new Error(`This device syncs with "${current.username}". Sign out of that account first.`);
	}
	if (!(await vault.hasVault())) {
		await vault.createVaultFromAccount(r.kdf, r.wrappedVaultKey, raw);
	} else if (!vault.isUnlocked()) {
		throw new Error("Unlock the vault first");
	} else {
		const local = vault.sessionVaultKey();
		const same = local.length === raw.length && local.every((b, i) => b === raw[i]);
		local.fill(0);
		if (same) await vault.setPasswordWrap(r.kdf, r.wrappedVaultKey);
		else await vault.adoptVaultKey(raw, r.kdf, r.wrappedVaultKey);
	}
	if (!current) await setSyncState({ ...EMPTY_SYNC });
	await saveAccount(r);
	await setSyncState({ status: "ok", message: undefined });
	emit();
}

export async function signIn(username: string, password: string, totp?: string): Promise<void> {
	const { r, raw } = await passwordLogin(username.trim().toLowerCase(), password, totp);
	await linkLocal(r, raw);
	void syncNow();
}

/**
 * Create an account from an invite. The account uses this device's existing vault key, so local
 * entries upload as they are. Returns the recovery key, to show the user exactly once.
 */
export async function joinWithInvite(invite: string, username: string, password: string): Promise<string> {
	const err = validatePassword(password);
	if (err) throw new Error(err);
	if (await getAccount()) throw new Error("This device is already signed in to an account");
	const vk = vault.sessionVaultKey();
	try {
		const { material, recoveryKey } = await makeAccountMaterial(password, vk);
		const r = await api<AccountResponse>("POST", "/register", { invite, username: username.trim().toLowerCase(), ...material });
		await vault.setPasswordWrap(r.kdf, r.wrappedVaultKey);
		await setSyncState({ ...EMPTY_SYNC });
		await saveAccount(r);
		await markAllDirty();
		emit();
		void syncNow();
		return recoveryKey;
	} finally {
		vk.fill(0);
	}
}

/** Reset the account password with the recovery key. Also turns off login TOTP on the server. */
export async function recoverAccount(username: string, recoveryKey: string, newPassword: string): Promise<void> {
	const err = validatePassword(newPassword);
	if (err) throw new Error(err);
	const u = username.trim().toLowerCase();
	const key = parseRecoveryKey(recoveryKey);
	const { authKey } = await recoverySubkeys(key);
	const proof = toB64(authKey);
	const { recoveryWrappedKey } = await api<{ recoveryWrappedKey: Sealed }>("POST", "/recover/start", { username: u, recoveryAuthKey: proof });
	let raw: Uint8Array;
	try {
		raw = await unwrapWithRecovery(key, recoveryWrappedKey);
	} catch (e) {
		if (e instanceof DecryptError) throw new Error("Recovery key does not match this account");
		throw e;
	}
	const pw = await makePasswordMaterial(newPassword, raw);
	const r = await api<AccountResponse>("POST", "/recover/finish", { username: u, recoveryAuthKey: proof, ...pw });
	const current = await getAccount();
	if (current && current.userId === r.user.id && (await vault.hasVault())) {
		// Same vault key as this device's vault: just re-wrap it with the new password.
		await vault.setPasswordWrap(r.kdf, r.wrappedVaultKey);
		await saveAccount(r);
	} else {
		await linkLocal(r, raw);
	}
}

export async function signOut(): Promise<void> {
	await api("POST", "/logout", {}).catch(() => {});
	await meta.delete("account");
	await meta.delete("sync");
	emit();
}

/** Change the master password. When linked, the server must accept it first (requires network). */
export async function changePassword(current: string, next: string): Promise<void> {
	const account = await getAccount();
	if (!account) return vault.changePassword(current, next);
	const err = validatePassword(next);
	if (err) throw new Error(err);
	const { kdf } = await api<{ kdf: KdfParams }>("POST", "/prelogin", { username: account.username });
	const { authKey } = await deriveKeys(current, kdf);
	const vk = vault.sessionVaultKey();
	try {
		const pw = await makePasswordMaterial(next, vk);
		const r = await api<AccountResponse>("POST", "/account/password", { currentAuthKey: toB64(authKey), ...pw });
		await vault.setPasswordWrap(r.kdf, r.wrappedVaultKey);
	} catch (e) {
		if (e instanceof ApiError && e.code === "invalid_credentials") throw new Error("Current master password is wrong");
		throw e;
	} finally {
		vk.fill(0);
	}
}

// --- login TOTP -----------------------------------------------------------------------------

export const totpSetup = () => api<{ secret: string; uri: string }>("POST", "/account/totp/setup", {});

export async function totpEnable(code: string): Promise<void> {
	await api("POST", "/account/totp/enable", { code });
	const a = await getAccount();
	if (a) await meta.put("account", { ...a, totpEnabled: true });
	emit();
}

export async function totpDisable(password: string): Promise<void> {
	const a = (await getAccount())!;
	const { kdf } = await api<{ kdf: KdfParams }>("POST", "/prelogin", { username: a.username });
	const { authKey } = await deriveKeys(password, kdf);
	await api("POST", "/account/totp/disable", { authKey: toB64(authKey) });
	await meta.put("account", { ...a, totpEnabled: false });
	emit();
}

// --- admin ------------------------------------------------------------------------------------

export const createInvite = (role: "user" | "admin" = "user", ttlHours = 24) =>
	api<{ id: string; token: string; expiresAt: number }>("POST", "/admin/invites", { role, ttlHours });
export const listInvites = () => api<{ invites: Invite[] }>("GET", "/admin/invites").then((r) => r.invites);
export const revokeInvite = (id: string) => api("DELETE", `/admin/invites/${encodeURIComponent(id)}`);
export const inviteLink = (token: string) => `${location.origin}/#invite=${token}`;
export const checkInvite = (token: string) =>
	api<{ valid: boolean; expiresAt: number | null }>("GET", `/invites/check?token=${encodeURIComponent(token)}`);

// --- sync -------------------------------------------------------------------------------------

async function markAllDirty() {
	const all = await records.all();
	await records.putMany(all.map((r) => ({ ...r, dirty: true })));
}

let inFlight: Promise<void> | null = null;

/** Push local changes, then pull remote ones. Safe to call often; concurrent calls share one run. */
export function syncNow(): Promise<void> {
	inFlight ??= runSync().finally(() => {
		inFlight = null;
	});
	return inFlight;
}

async function runSync(): Promise<void> {
	if (!(await getAccount()) || !vault.isUnlocked()) return;
	try {
		const rejected = await push();
		await pull(rejected ? 0 : undefined);
		await setSyncState({ lastSyncAt: Date.now(), status: "ok", message: undefined });
	} catch (e) {
		if (e instanceof ApiError && e.status === 401) {
			await setSyncState({ status: "signed_out", message: "Session expired. Sign in again to keep syncing." });
		} else if (e instanceof ApiError) {
			await setSyncState({ status: "error", message: e.message });
		} else {
			await setSyncState({ status: "offline", message: "Offline. Will sync when you are back online." });
		}
	} finally {
		emit();
	}
}

/** Returns true if the server rejected a change as stale (then a full pull reconciles). */
async function push(): Promise<boolean> {
	const dirty = (await records.all()).filter((r) => r.dirty);
	let rejected = false;
	for (let i = 0; i < dirty.length; i += 200) {
		const batch = dirty.slice(i, i + 200);
		const { results } = await api<{ results: { id: string; accepted: boolean }[] }>("POST", "/sync", {
			changes: batch.map(({ id, iv, ct, revision, updatedAt, deleted }) => ({ id, iv, ct, revision, updatedAt, deleted })),
		});
		const sent = new Map(batch.map((r) => [r.id, r]));
		const clean: EntryRecord[] = [];
		for (const res of results) {
			if (!res.accepted) {
				rejected = true;
				continue;
			}
			const was = sent.get(res.id)!;
			const now = await records.get(res.id);
			// Only clear the flag if the record was not edited again while we were pushing.
			if (now && now.updatedAt === was.updatedAt && now.revision === was.revision) clean.push({ ...now, dirty: false });
		}
		if (clean.length) await records.putMany(clean);
	}
	return rejected;
}

/** Remote wins unless the local copy is dirty and newer (same rule as the server). */
function remoteWins(local: EntryRecord | undefined, remote: RemoteRecord): boolean {
	if (!local || !local.dirty) return true;
	return remote.updatedAt > local.updatedAt || (remote.updatedAt === local.updatedAt && remote.revision >= local.revision);
}

async function pull(fromCursor?: number): Promise<void> {
	let cursor = fromCursor ?? (await getSyncState()).cursor;
	let changed = false;
	for (;;) {
		const page = await api<{ entries: RemoteRecord[]; cursor: number; more: boolean }>("GET", `/sync?since=${cursor}`);
		const updates: EntryRecord[] = [];
		for (const rem of page.entries) {
			const local = await records.get(rem.id);
			if (local && !local.dirty && local.revision === rem.revision && local.updatedAt === rem.updatedAt) continue;
			if (remoteWins(local, rem)) {
				updates.push({ id: rem.id, iv: rem.iv, ct: rem.ct, revision: rem.revision, updatedAt: rem.updatedAt, deleted: rem.deleted, dirty: false });
			}
		}
		if (updates.length) {
			await records.putMany(updates);
			changed = true;
		}
		cursor = page.cursor;
		await setSyncState({ cursor });
		if (!page.more) break;
	}
	if (changed) vault.notifyRemoteChange();
}
