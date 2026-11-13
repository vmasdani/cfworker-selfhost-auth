// Google Authenticator "Transfer accounts" QR codes: otpauth-migration://offline?data=<base64 protobuf>
//
// message MigrationPayload {
//   repeated OtpParameters otp_parameters = 1;
//   int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
// }
// message OtpParameters {
//   bytes secret = 1; string name = 2; string issuer = 3;
//   Algorithm algorithm = 4;   // 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
//   DigitCount digits = 5;     // 0 unspecified, 1 SIX, 2 EIGHT
//   OtpType type = 6;          // 0 unspecified, 1 HOTP, 2 TOTP
//   int64 counter = 7;
// }
// The format has no period field: Google always uses 30 seconds.

import { base32Decode, base32Encode, validateOtpParams, type OtpAlgorithm } from "@cfsa/totp";
import { decodeFields, toSigned, Writer, type Field } from "./protobuf.ts";
import { ImportError, type ImportedEntry, type ImportResult } from "./types.ts";

export interface MigrationBatch {
	index: number;
	size: number;
	id: number;
}

export interface GoogleImportResult extends ImportResult {
	format: "google-migration";
	batch: MigrationBatch;
}

const ALGORITHMS: Record<number, OtpAlgorithm> = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
const ALGORITHM_CODES: Record<OtpAlgorithm, number> = { SHA1: 1, SHA256: 2, SHA512: 3 };

export function isGoogleMigrationUri(s: string): boolean {
	return /^otpauth-migration:\/\//i.test(s.trim());
}

function decodeData(uri: string): Uint8Array {
	let url: URL;
	try {
		url = new URL(uri.trim());
	} catch {
		throw new ImportError("Not a valid otpauth-migration URI");
	}
	const data = url.searchParams.get("data");
	if (!data) throw new ImportError("otpauth-migration URI has no data");
	// searchParams decodes %2B etc.; a raw "+" may arrive as a space.
	const b64 = data.replace(/ /g, "+").replace(/-/g, "+").replace(/_/g, "/");
	try {
		return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
	} catch {
		throw new ImportError("otpauth-migration data is not valid base64");
	}
}

const str = (f: Field | undefined) => (f && f.value instanceof Uint8Array ? new TextDecoder().decode(f.value) : "");
const num = (f: Field | undefined) => (f && typeof f.value === "bigint" ? toSigned(f.value) : 0);

export function parseGoogleMigrationUri(uri: string): GoogleImportResult {
	let top: Field[];
	try {
		top = decodeFields(decodeData(uri));
	} catch (e) {
		if (e instanceof ImportError) throw e;
		throw new ImportError("otpauth-migration payload is corrupted");
	}
	const entries: ImportedEntry[] = [];
	const warnings: string[] = [];
	let n = 0;
	for (const f of top) {
		if (f.no !== 1 || !(f.value instanceof Uint8Array)) continue;
		n++;
		const p = decodeFields(f.value);
		const get = (no: number) => p.find((x) => x.no === no);
		const secret = get(1)?.value;
		const name = str(get(2));
		const issuer = str(get(3));
		const algCode = num(get(4));
		const digitCode = num(get(5));
		const typeCode = num(get(6));
		const label = issuer || name || `account #${n}`;

		const algorithm = ALGORITHMS[algCode];
		if (!algorithm) {
			warnings.push(`Skipped "${label}": unsupported algorithm (${algCode === 4 ? "MD5" : algCode})`);
			continue;
		}
		if (typeCode !== 1 && typeCode !== 2) {
			warnings.push(`Skipped "${label}": unknown OTP type`);
			continue;
		}
		if (!(secret instanceof Uint8Array) || secret.length === 0) {
			warnings.push(`Skipped "${label}": empty secret`);
			continue;
		}
		// Name is often "Issuer:account"; drop the duplicated issuer prefix. The issuer itself may
		// contain ":", so match the exact issuer first and only split on ":" when there is none.
		let account = name;
		let iss = issuer;
		if (iss && name.startsWith(`${iss}:`)) account = name.slice(iss.length + 1).trim();
		else if (!iss && name.includes(":")) {
			const colon = name.indexOf(":");
			iss = name.slice(0, colon).trim();
			account = name.slice(colon + 1).trim();
		}
		try {
			entries.push({
				...validateOtpParams({
					type: typeCode === 1 ? "hotp" : "totp",
					issuer: iss,
					account,
					secret: base32Encode(secret, { padding: false }),
					algorithm,
					digits: digitCode === 2 ? 8 : 6,
					period: 30,
					counter: typeCode === 1 ? num(get(7)) : 0,
				}),
				note: "",
			});
		} catch (e) {
			warnings.push(`Skipped "${label}": ${e instanceof Error ? e.message : "invalid"}`);
		}
	}
	const meta = (no: number) => num(top.find((x) => x.no === no));
	return {
		format: "google-migration",
		entries,
		warnings,
		batch: { index: meta(4), size: Math.max(meta(3), 1), id: meta(5) },
	};
}

export interface GoogleExport {
	uris: string[];
	/** Entries that Google Authenticator cannot represent. */
	skipped: { entry: ImportedEntry; reason: string }[];
}

/** Encode entries as Google Authenticator migration URIs, `perBatch` accounts per QR code. */
export function encodeGoogleMigration(entries: ImportedEntry[], perBatch = 10): GoogleExport {
	const ok: ImportedEntry[] = [];
	const skipped: GoogleExport["skipped"] = [];
	for (const e of entries) {
		if (e.digits !== 6 && e.digits !== 8) skipped.push({ entry: e, reason: `${e.digits} digits` });
		else if (e.type === "totp" && e.period !== 30) skipped.push({ entry: e, reason: `${e.period}s period` });
		else ok.push(e);
	}
	const batches: ImportedEntry[][] = [];
	for (let i = 0; i < ok.length; i += perBatch) batches.push(ok.slice(i, i + perBatch));
	const id = crypto.getRandomValues(new Uint32Array(1))[0]! & 0x7fffffff;
	const uris = batches.map((batch, index) => {
		const w = new Writer();
		for (const e of batch) {
			const p = new Writer()
				.bytes(1, base32Decode(e.secret))
				.string(2, e.issuer ? `${e.issuer}:${e.account}` : e.account)
				.string(3, e.issuer)
				.varint(4, ALGORITHM_CODES[e.algorithm])
				.varint(5, e.digits === 8 ? 2 : 1)
				.varint(6, e.type === "hotp" ? 1 : 2);
			if (e.type === "hotp") p.varint(7, e.counter);
			w.bytes(1, p.finish());
		}
		w.varint(2, 1).varint(3, batches.length).varint(4, index).varint(5, id);
		return `otpauth-migration://offline?data=${encodeURIComponent(btoa(String.fromCharCode(...w.finish())))}`;
	});
	return { uris, skipped };
}
