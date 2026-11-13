import { describe, expect, test } from "bun:test";
import type { ImportedEntry } from "@cfsa/importers";
import { BackupPasswordError, createBackup, isTumblerBackup, openBackup } from "../backup.ts";

const entries: ImportedEntry[] = [
	{ type: "totp", issuer: "Example", account: "alice", secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, counter: 0, note: "n" },
	{ type: "hotp", issuer: "", account: "bob", secret: "GEZDGNBVGY3TQOJQ", algorithm: "SHA256", digits: 8, period: 30, counter: 5, note: "" },
];

describe("tumbler backup", () => {
	test("round-trip; file has no plaintext secrets", async () => {
		const text = await createBackup(entries, "backup passphrase", 1000);
		expect(text).not.toContain("JBSWY3DPEHPK3PXP");
		expect(text).not.toContain("alice");
		const parsed = JSON.parse(text);
		expect(isTumblerBackup(parsed)).toBe(true);
		expect(await openBackup(parsed, "backup passphrase")).toEqual(entries);
	});
	test("wrong password", async () => {
		const parsed = JSON.parse(await createBackup(entries, "backup passphrase", 1000));
		await expect(openBackup(parsed, "nope")).rejects.toBeInstanceOf(BackupPasswordError);
	});
	test("strips vault-only fields", async () => {
		const withIds = entries.map((e) => ({ ...e, id: "x", createdAt: 1, updatedAt: 2 }));
		const parsed = JSON.parse(await createBackup(withIds, "backup passphrase", 1000));
		expect(await openBackup(parsed, "backup passphrase")).toEqual(entries);
	});
});
