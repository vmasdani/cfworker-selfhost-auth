import { describe, expect, test } from "bun:test";
import {
	encodeGoogleMigration,
	entryIdentity,
	formatProtonExport,
	formatUriList,
	ImportError,
	parseGoogleMigrationUri,
	parseImport,
	parseProtonExport,
	type ImportedEntry,
} from "../src/index.ts";

// Hand-assembled payload, byte layout checked against the proto (not produced by our encoder):
//   0a 35 { 0a 0a "Hello!\xde\xad\xbe\xef"  12 18 "Example:alice@google.com"  1a 07 "Example"
//           20 01 (SHA1)  28 01 (SIX)  30 02 (TOTP) }
//   10 01 (version)  18 01 (batch_size)  20 00 (batch_index)  28 <-1857769365 as int32 varint>
const GOOGLE_SAMPLE =
	"otpauth-migration://offline?data=CjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhABGAEgACjr4JKK%2Bf%2F%2F%2F%2F8B";

const entry = (over: Partial<ImportedEntry> = {}): ImportedEntry => ({
	type: "totp",
	issuer: "Example",
	account: "alice@example.com",
	secret: "JBSWY3DPEHPK3PXP",
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	counter: 0,
	note: "",
	...over,
});

describe("Google Authenticator migration", () => {
	test("decodes published sample", () => {
		const r = parseGoogleMigrationUri(GOOGLE_SAMPLE);
		expect(r.warnings).toEqual([]);
		expect(r.entries).toEqual([
			entry({ account: "alice@google.com" }),
		]);
		expect(r.batch).toEqual({ index: 0, size: 1, id: -1857769365 });
	});

	test("encode/decode round-trip incl. HOTP, SHA512, 8 digits; batches of 10", () => {
		const entries = [
			...Array.from({ length: 12 }, (_, i) => entry({ account: `user${i}`, secret: "GEZDGNBVGY3TQOJQ" })),
			entry({ type: "hotp", counter: 42, issuer: "", account: "plain" }),
			entry({ algorithm: "SHA512", digits: 8, issuer: "Big Co", account: "me" }),
		];
		const { uris, skipped } = encodeGoogleMigration(entries);
		expect(skipped).toEqual([]);
		expect(uris.length).toBe(2);
		const decoded = uris.map(parseGoogleMigrationUri);
		expect(decoded.map((d) => d.batch.index)).toEqual([0, 1]);
		expect(decoded.every((d) => d.batch.size === 2 && d.batch.id === decoded[0]!.batch.id)).toBe(true);
		expect(decoded.flatMap((d) => d.entries)).toEqual(entries);
	});

	test("issuer containing a colon survives", () => {
		const e = entry({ issuer: "Acme: EU", account: "bob" });
		expect(parseGoogleMigrationUri(encodeGoogleMigration([e]).uris[0]!).entries).toEqual([e]);
	});

	test("skips what Google cannot represent", () => {
		const { uris, skipped } = encodeGoogleMigration([entry({ period: 60 }), entry({ digits: 7 }), entry()]);
		expect(skipped.map((s) => s.reason)).toEqual(["60s period", "7 digits"]);
		expect(uris.length).toBe(1);
	});

	test("rejects garbage", () => {
		expect(() => parseGoogleMigrationUri("otpauth-migration://offline")).toThrow(ImportError);
		expect(() => parseGoogleMigrationUri("otpauth-migration://offline?data=%FF%FF")).toThrow();
	});
});

describe("Proton Authenticator", () => {
	const sample = {
		version: 1,
		entries: [
			{
				id: "6e7b0b5e-0000-4000-8000-000000000001",
				content: {
					uri: "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
					entry_type: "Totp",
					name: "alice@example.com",
				},
				note: null,
			},
			{
				id: "6e7b0b5e-0000-4000-8000-000000000002",
				content: { uri: "steam://whatever", entry_type: "Steam", name: "Steam" },
				note: null,
			},
		],
	};

	test("parses entries; name is the account label; skips unsupported types", () => {
		const r = parseProtonExport(sample);
		expect(r.entries).toEqual([entry()]);
		expect(r.warnings).toEqual(['Skipped "Steam": unsupported type Steam']);
	});

	test("export round-trip", () => {
		const entries = [entry({ note: "backup codes in safe" }), entry({ issuer: "", account: "solo", digits: 8 })];
		const r = parseProtonExport(JSON.parse(formatProtonExport(entries)));
		expect(r.entries).toEqual(entries);
	});

	test("password-protected export gives a clear error", () => {
		expect(() => parseProtonExport({ version: 1, salt: "x", content: "y" })).toThrow(/password-protected/);
	});
});

describe("auto-detect", () => {
	test("URI list with comments, a migration line and a bad line", () => {
		const text = [
			"# exported",
			"otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			GOOGLE_SAMPLE,
			"otpauth://totp/x?secret=!!!",
			"",
		].join("\n");
		const r = parseImport(text);
		expect(r.entries.length).toBe(2);
		expect(r.warnings).toEqual(["Line 4: Secret is not valid base32"]);
	});
	test("URI list round-trip", () => {
		const entries = [entry(), entry({ type: "hotp", counter: 3, account: "h" })];
		expect(parseImport(formatUriList(entries)).entries).toEqual(entries);
	});
	test("JSON goes to Proton parser", () => {
		expect(parseImport(JSON.stringify({ version: 1, entries: [] })).format).toBe("proton");
		expect(() => parseImport("{ nope")).toThrow(ImportError);
		expect(() => parseImport("   ")).toThrow(ImportError);
	});
	test("warnings never contain the secret", () => {
		const r = parseImport("otpauth://totp/x?secret=SECRETVALUE1&digits=99");
		expect(r.warnings.join(" ")).not.toContain("SECRETVALUE1");
	});
	test("identity ignores formatting", () => {
		expect(entryIdentity({ type: "totp", secret: "jbsw y3dp ehpk 3pxp" })).toBe(entryIdentity(entry()));
	});
});
