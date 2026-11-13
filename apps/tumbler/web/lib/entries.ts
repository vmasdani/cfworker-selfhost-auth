import { openJSON, sealJSON } from "@cfsa/crypto";
import type { OtpParams } from "@cfsa/totp";

/** Decrypted authenticator entry. Exists only in memory while unlocked. */
export interface Entry extends OtpParams {
	id: string;
	note: string;
	createdAt: number;
	updatedAt: number;
}

/** Stored form: one encrypted record per entry. Mirrors the server `entries` table for sync. */
export interface EntryRecord {
	id: string;
	iv: string;
	ct: string;
	updatedAt: number;
	revision: number;
	deleted: boolean;
	/** Changed locally since last sync. */
	dirty: boolean;
}

/** Binds ciphertext to its entry id, so records cannot be swapped. */
export const entryAad = (id: string) => `tumbler/entry/v1/${id}`;

export async function sealEntry(key: CryptoKey, entry: Entry, prev?: EntryRecord): Promise<EntryRecord> {
	const { iv, ct } = await sealJSON(key, entry, entryAad(entry.id));
	return {
		id: entry.id,
		iv,
		ct,
		updatedAt: entry.updatedAt,
		revision: (prev?.revision ?? 0) + 1,
		deleted: false,
		dirty: true,
	};
}

export function openEntry(key: CryptoKey, rec: EntryRecord): Promise<Entry> {
	return openJSON<Entry>(key, { iv: rec.iv, ct: rec.ct }, entryAad(rec.id));
}

export function compareEntries(a: Entry, b: Entry): number {
	return (
		a.issuer.localeCompare(b.issuer, undefined, { sensitivity: "base" }) ||
		a.account.localeCompare(b.account, undefined, { sensitivity: "base" })
	);
}

export function matchesQuery(e: Entry, q: string): boolean {
	const s = q.trim().toLowerCase();
	return !s || e.issuer.toLowerCase().includes(s) || e.account.toLowerCase().includes(s);
}
