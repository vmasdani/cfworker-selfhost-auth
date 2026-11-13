// Stateful local vault: IndexedDB storage + in-memory unlocked session.

import { DecryptError, importAesKey } from "@cfsa/crypto";
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
}

export const DEFAULT_SETTINGS: Settings = { autoLockMinutes: 5, clipboardClearSeconds: 30 };

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
}

export async function deleteEntry(id: string): Promise<void> {
	requireSession();
	const prev = await records.get(id);
	if (!prev) return;
	// Tombstone: keep the id for sync, drop the ciphertext.
	await records.putMany([
		{ id, iv: "", ct: "", updatedAt: Date.now(), revision: prev.revision + 1, deleted: true, dirty: true },
	]);
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
