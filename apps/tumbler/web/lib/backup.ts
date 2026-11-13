// Tumbler encrypted backup file. Independent of the vault key: protected by a backup password
// (PBKDF2-SHA256 600k -> HKDF -> AES-256-GCM), so it can be restored on any device.

import { DecryptError, deriveKeys, newKdfParams, openJSON, sealJSON, type KdfParams, type Sealed } from "@cfsa/crypto";
import type { ImportedEntry } from "@cfsa/importers";

const AAD = "tumbler/backup/v1";

export interface TumblerBackup {
	format: "tumbler-backup";
	version: 1;
	createdAt: string;
	kdf: KdfParams;
	data: Sealed;
}

interface Payload {
	entries: ImportedEntry[];
}

export function isTumblerBackup(value: unknown): value is TumblerBackup {
	return typeof value === "object" && value !== null && (value as TumblerBackup).format === "tumbler-backup";
}

export async function createBackup(entries: ImportedEntry[], password: string, iterations?: number): Promise<string> {
	const kdf = newKdfParams(iterations);
	const { wrapKey } = await deriveKeys(password, kdf);
	const payload: Payload = {
		entries: entries.map(({ type, issuer, account, secret, algorithm, digits, period, counter, note }) => ({
			type, issuer, account, secret, algorithm, digits, period, counter, note,
		})),
	};
	const backup: TumblerBackup = {
		format: "tumbler-backup",
		version: 1,
		createdAt: new Date().toISOString(),
		kdf,
		data: await sealJSON(wrapKey, payload, AAD),
	};
	return JSON.stringify(backup, null, 2);
}

export class BackupPasswordError extends Error {
	override name = "BackupPasswordError";
	constructor() {
		super("Wrong backup password, or the file is damaged");
	}
}

export async function openBackup(backup: TumblerBackup, password: string): Promise<ImportedEntry[]> {
	if (backup.version !== 1) throw new Error(`Unsupported backup version ${backup.version}`);
	const { wrapKey } = await deriveKeys(password, backup.kdf);
	try {
		return (await openJSON<Payload>(wrapKey, backup.data, AAD)).entries;
	} catch (e) {
		if (e instanceof DecryptError) throw new BackupPasswordError();
		throw e;
	}
}

/** Trigger a file download without leaving the page. */
export function downloadFile(name: string, content: string, type: string): void {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const a = document.createElement("a");
	a.href = url;
	a.download = name;
	document.body.append(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export const today = () => new Date().toISOString().slice(0, 10);
