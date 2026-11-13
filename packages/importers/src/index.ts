// Import/export: Proton Authenticator JSON, Google Authenticator otpauth-migration, otpauth URI lists.

import { formatOtpauthUri, normalizeBase32, parseOtpauthUri } from "@cfsa/totp";
import { isGoogleMigrationUri, parseGoogleMigrationUri } from "./google.ts";
import { parseProtonExport } from "./proton.ts";
import { ImportError, type ImportedEntry, type ImportResult } from "./types.ts";

export * from "./google.ts";
export * from "./proton.ts";
export * from "./types.ts";

/** Lines of otpauth:// and/or otpauth-migration:// URIs. Blank lines and # comments are ignored. */
export function parseUriList(text: string): ImportResult {
	const entries: ImportedEntry[] = [];
	const warnings: string[] = [];
	let sawMigration = false;
	text.split(/\r?\n/).forEach((raw, i) => {
		const line = raw.trim();
		if (!line || line.startsWith("#")) return;
		try {
			if (isGoogleMigrationUri(line)) {
				sawMigration = true;
				const r = parseGoogleMigrationUri(line);
				entries.push(...r.entries);
				warnings.push(...r.warnings);
			} else {
				entries.push({ ...parseOtpauthUri(line), note: "" });
			}
		} catch (e) {
			warnings.push(`Line ${i + 1}: ${e instanceof Error ? e.message : "invalid"}`);
		}
	});
	return { format: sawMigration && entries.length > 0 ? "google-migration" : "otpauth-uri-list", entries, warnings };
}

/** Auto-detect and parse an export file or pasted text. */
export function parseImport(text: string): ImportResult {
	const t = text.trim();
	if (!t) throw new ImportError("Nothing to import");
	if (t.startsWith("{")) {
		let json: unknown;
		try {
			json = JSON.parse(t);
		} catch {
			throw new ImportError("File is not valid JSON");
		}
		return parseProtonExport(json);
	}
	const r = parseUriList(t);
	if (r.entries.length === 0 && r.warnings.length === 0) throw new ImportError("No otpauth:// URIs found");
	return r;
}

export function formatUriList(entries: ImportedEntry[]): string {
	return `${entries.map((e) => formatOtpauthUri(e)).join("\n")}\n`;
}

/** Identity for duplicate detection: same type and secret means the same account. */
export function entryIdentity(e: { type: string; secret: string }): string {
	return `${e.type}:${normalizeBase32(e.secret)}`;
}
