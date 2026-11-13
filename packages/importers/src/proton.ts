// Proton Authenticator export (unencrypted, version 1):
// { "version": 1, "entries": [ { "id": "<uuid>", "content": { "uri": "otpauth://...",
//   "entry_type": "Totp", "name": "<account label>" }, "note": null } ] }

import { formatOtpauthUri, parseOtpauthUri } from "@cfsa/totp";
import { ImportError, type ImportedEntry, type ImportResult } from "./types.ts";

interface ProtonEntry {
	id?: string;
	content?: { uri?: string; entry_type?: string; name?: string };
	note?: string | null;
}

interface ProtonExport {
	version?: number;
	entries?: ProtonEntry[];
}

export function isProtonExport(value: unknown): value is ProtonExport {
	return typeof value === "object" && value !== null && Array.isArray((value as ProtonExport).entries) &&
		typeof (value as ProtonExport).version === "number";
}

export function parseProtonExport(value: unknown): ImportResult {
	if (!isProtonExport(value)) {
		const keys = typeof value === "object" && value !== null ? Object.keys(value) : [];
		if (keys.some((k) => /salt|encrypted|nonce|cipher/i.test(k))) {
			throw new ImportError("This Proton Authenticator export is password-protected. Export again without a password, then delete the file after importing.");
		}
		throw new ImportError("Not a Proton Authenticator export");
	}
	if (value.version !== 1) throw new ImportError(`Unsupported Proton export version ${value.version}`);

	const entries: ImportedEntry[] = [];
	const warnings: string[] = [];
	value.entries!.forEach((e, i) => {
		const label = e.content?.name || `entry #${i + 1}`;
		const type = e.content?.entry_type ?? "Totp";
		if (type.toLowerCase() !== "totp" && type.toLowerCase() !== "hotp") {
			warnings.push(`Skipped "${label}": unsupported type ${type}`);
			return;
		}
		if (!e.content?.uri) {
			warnings.push(`Skipped "${label}": missing URI`);
			return;
		}
		try {
			const p = parseOtpauthUri(e.content.uri);
			entries.push({ ...p, account: e.content.name?.trim() || p.account, note: e.note ?? "" });
		} catch (err) {
			warnings.push(`Skipped "${label}": ${err instanceof Error ? err.message : "invalid URI"}`);
		}
	});
	return { format: "proton", entries, warnings };
}

export function formatProtonExport(entries: ImportedEntry[]): string {
	const out: ProtonExport = {
		version: 1,
		entries: entries.map((e) => ({
			id: crypto.randomUUID(),
			content: {
				uri: formatOtpauthUri(e),
				entry_type: e.type === "hotp" ? "Hotp" : "Totp",
				name: e.account || e.issuer,
			},
			note: e.note || null,
		})),
	};
	return JSON.stringify(out, null, 2);
}
