import type { OtpParams } from "@cfsa/totp";

export interface ImportedEntry extends OtpParams {
	note: string;
}

export type ImportFormat = "proton" | "google-migration" | "otpauth-uri-list";

export interface ImportResult {
	format: ImportFormat;
	entries: ImportedEntry[];
	/** Human-readable problems. Never contains secrets. */
	warnings: string[];
}

export class ImportError extends Error {
	override name = "ImportError";
}
