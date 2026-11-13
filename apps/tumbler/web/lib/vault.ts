// Stateful local vault: IndexedDB storage + in-memory unlocked session.

import { DecryptError, importAesKey, type KdfParams, type Sealed } from "@cfsa/crypto";
import type { ImportedEntry } from "@cfsa/importers";
import { compareEntries, openEntry, sealEntry, type Entry, type EntryRecord } from "./entries.ts";
import { meta, records, requestPersistence } from "./idb.ts";
import { clearOtpKeys } from "./otp-keys.ts";
import {
	createHeader,
	MAX_PIN_FAILURES,
	unwrapWithSecret,
	validatePassword,
	validatePin,
	wrapWithSecret,
	type VaultHeader,
} from "./vault-core.ts";

export interface Settings {
	autoLockMinutes: number;
	clipboardClearSeconds: number;
	/** Show the upcoming TOTP code under the current one. */
	showNextCode: boolean;
}

export const DEFAULT_SETTINGS: Settings = { autoLockMinutes: 5, clipboardClearSeconds: 30, showNextCode: true };

export class PinError extends Error {
	override name = "PinError";
	constructor(readonly remaining: number) {
		super(remaining > 0 ? `Wrong PIN. ${remaining} attempt(s) left.` : "Too many wrong PINs. PIN unlock disabled; use your master password.");
	}
}

interface Session {
	key: CryptoKey;
	/** Raw vault key; kept only while unlocked so a PIN or new password can re-wrap it. */
	raw: Uint8Array;
}

let session: Session | null = null;

/** Fires "change" after local edits and "remote" after sync wrote records. */
export const vaultEvents = new EventTarget();
const notify = (type: "change" | "remote") => vaultEvents.dispatchEvent(new Event(type));
export const notifyRemoteChange = () => notify("remote");

const getHeader = () => meta.get<VaultHeader>("vault");
const putHeader = (h: VaultHeader) => meta.put("vault", h);

async function startSession(raw: Uint8Array): Promise<void> {
	session = { key: await importAesKey(raw), raw };
}

function requireSession(): Session {
	if (!session) throw new Error("Vault is locked");
	return session;
}

export async function vaultState(): Promise<{ exists: boolean; hasPin: boolean }> {
	const h = await getHeader();
	return { exists: !!h, hasPin: !!h?.pin };
}

export async function createVault(password: string, pin?: string): Promise<void> {
	if (await getHeader()) throw new Error("A vault already exists on this device");
	const { header, vaultKey } = await createHeader(password, pin);
	await putHeader(header);
	await startSession(vaultKey);
	void requestPersistence();
}

export async function unlockWithPassword(password: string): Promise<void> {
	const h = await getHeader();
	if (!h) throw new Error("No vault on this device");
	let raw: Uint8Array;
	try {
		raw = await unwrapWithSecret(password, h.kdf, h.wrapped);
	} catch (e) {
		if (e instanceof DecryptError) throw new Error("Wrong master password");
		throw e;
	}
	if (h.pin && h.pin.failures > 0) await putHeader({ ...h, pin: { ...h.pin, failures: 0 } });
	await startSession(raw);
}

export async function unlockWithPin(pin: string): Promise<void> {
	const h = await getHeader();
	if (!h?.pin) throw new PinError(0);
	try {
		const raw = await unwrapWithSecret(pin, h.pin.kdf, h.pin.wrapped);
		if (h.pin.failures > 0) await putHeader({ ...h, pin: { ...h.pin, failures: 0 } });
		await startSession(raw);
	} catch (e) {
		if (!(e instanceof DecryptError)) throw e;
		const failures = h.pin.failures + 1;
		const remaining = MAX_PIN_FAILURES - failures;
		if (remaining <= 0) {
			const { pin: _removed, ...rest } = h;
			await putHeader(rest);
		} else {
			await putHeader({ ...h, pin: { ...h.pin, failures } });
		}
		throw new PinError(Math.max(remaining, 0));
	}
}

export function lock(): void {
	session?.raw.fill(0);
	session = null;
	clearOtpKeys();
}

export const isUnlocked = () => session !== null;

export async function setPin(pin: string): Promise<void> {
	const err = validatePin(pin);
	if (err) throw new Error(err);
	const s = requireSession();
	const h = await getHeader();
	if (!h) throw new Error("No vault on this device");
	await putHeader({ ...h, pin: { ...(await wrapWithSecret(pin, s.raw)), failures: 0 } });
}

export async function removePin(): Promise<void> {
	const h = await getHeader();
	if (!h?.pin) return;
	const { pin: _removed, ...rest } = h;
	await putHeader(rest);
}

export async function changePassword(current: string, next: string): Promise<void> {
	const err = validatePassword(next);
	if (err) throw new Error(err);
	const s = requireSession();
	const h = await getHeader();
	if (!h) throw new Error("No vault on this device");
	try {
		await unwrapWithSecret(current, h.kdf, h.wrapped);
	} catch (e) {
		if (e instanceof DecryptError) throw new Error("Current master password is wrong");
		throw e;
	}
	await putHeader({ ...h, ...(await wrapWithSecret(next, s.raw)) });
}

export async function listEntries(): Promise<Entry[]> {
	const { key } = requireSession();
	const recs = (await records.all()).filter((r) => !r.deleted);
	const entries = await Promise.all(recs.map((r) => openEntry(key, r)));
	return entries.sort(compareEntries);
}

export async function saveEntries(entries: Entry[]): Promise<void> {
	const { key } = requireSession();
	const recs: EntryRecord[] = [];
	for (const e of entries) recs.push(await sealEntry(key, e, await records.get(e.id)));
	await records.putMany(recs);
	notify("change");
}

export async function deleteEntry(id: string): Promise<void> {
	requireSession();
	const prev = await records.get(id);
	if (!prev) return;
	// Tombstone: keep the id for sync, drop the ciphertext.
	await records.putMany([
		{ id, iv: "", ct: "", updatedAt: Date.now(), revision: prev.revision + 1, deleted: true, dirty: true },
	]);
	notify("change");
}

export async function getSettings(): Promise<Settings> {
	return { ...DEFAULT_SETTINGS, ...(await meta.get<Partial<Settings>>("settings")) };
}

export async function saveSettings(s: Settings): Promise<void> {
	await meta.put("settings", s);
}

export function newEntryId(): string {
	return crypto.randomUUID();
}

/** Re-check the master password, e.g. before showing or exporting secrets. */
export async function verifyMasterPassword(password: string): Promise<boolean> {
	const h = await getHeader();
	if (!h) return false;
	try {
		(await unwrapWithSecret(password, h.kdf, h.wrapped)).fill(0);
		return true;
	} catch (e) {
		if (e instanceof DecryptError) return false;
		throw e;
	}
}

/** Add imported accounts as new entries. Returns how many were added. */
export async function importEntries(items: ImportedEntry[]): Promise<number> {
	const now = Date.now();
	await saveEntries(
		items.map((item, i) => ({ ...item, id: newEntryId(), note: item.note ?? "", createdAt: now + i, updatedAt: now + i })),
	);
	return items.length;
}

// --- Account linking (see account.ts) ---

/** Copy of the raw vault key while unlocked, e.g. to wrap it for a new account. */
export function sessionVaultKey(): Uint8Array {
	return requireSession().raw.slice();
}

export async function hasVault(): Promise<boolean> {
	return !!(await getHeader());
}

/** New device signing in: the local vault is created from the account's wrapped vault key. */
export async function createVaultFromAccount(kdf: KdfParams, wrapped: Sealed, raw: Uint8Array): Promise<void> {
	if (await getHeader()) throw new Error("A vault already exists on this device");
	await putHeader({ v: 1, kdf, wrapped, createdAt: Date.now() });
	await startSession(raw);
	void requestPersistence();
}

/** The account password changed (here or elsewhere): re-wrap the same vault key. Keeps the PIN. */
export async function setPasswordWrap(kdf: KdfParams, wrapped: Sealed): Promise<void> {
	const h = await getHeader();
	if (!h) throw new Error("No vault on this device");
	if (h.kdf.salt === kdf.salt && h.wrapped.ct === wrapped.ct) return;
	await putHeader({ ...h, kdf, wrapped });
}

/**
 * Link this local vault to an existing account that has a different vault key: re-encrypt every
 * local entry under the account key and switch the header to the account password.
 * The PIN is removed because it wrapped the old key; the user can set it again.
 */
export async function adoptVaultKey(raw: Uint8Array, kdf: KdfParams, wrapped: Sealed): Promise<void> {
	const old = requireSession();
	const newKey = await importAesKey(raw);
	const all = await records.all();
	const next: EntryRecord[] = [];
	for (const r of all) {
		if (r.deleted) continue; // the account never knew these
		const entry = await openEntry(old.key, r);
		next.push({ ...(await sealEntry(newKey, entry)), updatedAt: r.updatedAt, revision: r.revision, dirty: true });
	}
	await records.replaceAll(next);
	const h = (await getHeader())!;
	await putHeader({ v: 1, kdf, wrapped, createdAt: h.createdAt });
	old.raw.fill(0);
	session = { key: newKey, raw };
	clearOtpKeys();
	notify("remote");
}
