import { describe, expect, test } from "bun:test";
import { DecryptError, timingSafeEqual } from "@cfsa/crypto";
import { createHeader, unwrapWithSecret, validatePassword, validatePin, wrapWithSecret } from "../vault-core.ts";
import { entryAad, openEntry, sealEntry, type Entry } from "../entries.ts";
import { importAesKey } from "@cfsa/crypto";
import { formatCode } from "../otp-keys.ts";

const IT = 1000;

describe("validation", () => {
	test("password", () => {
		expect(validatePassword("short")).not.toBeNull();
		expect(validatePassword("aaaaaaaaaaaaaaaa")).not.toBeNull();
		expect(validatePassword("long enough passphrase")).toBeNull();
	});
	test("pin", () => {
		expect(validatePin("1234567")).not.toBeNull();
		expect(validatePin("12345678")).not.toBeNull();
		expect(validatePin("87654321")).not.toBeNull();
		expect(validatePin("11111111")).not.toBeNull();
		expect(validatePin("1234abcd")).not.toBeNull();
		expect(validatePin("48201937")).toBeNull();
	});
});

describe("header", () => {
	test("password and PIN both unwrap the same vault key", async () => {
		const { header, vaultKey } = await createHeader("long enough passphrase", "48201937", IT);
		const viaPw = await unwrapWithSecret("long enough passphrase", header.kdf, header.wrapped);
		const viaPin = await unwrapWithSecret("48201937", header.pin!.kdf, header.pin!.wrapped);
		expect(timingSafeEqual(viaPw, vaultKey)).toBe(true);
		expect(timingSafeEqual(viaPin, vaultKey)).toBe(true);
		expect(header.kdf.salt).not.toBe(header.pin!.kdf.salt);
	});
	test("wrong secrets fail", async () => {
		const { header } = await createHeader("long enough passphrase", "48201937", IT);
		await expect(unwrapWithSecret("wrong passphrase!!", header.kdf, header.wrapped)).rejects.toBeInstanceOf(DecryptError);
		await expect(unwrapWithSecret("48201938", header.pin!.kdf, header.pin!.wrapped)).rejects.toBeInstanceOf(DecryptError);
	});
	test("rejects weak input", async () => {
		await expect(createHeader("short", undefined, IT)).rejects.toThrow();
		await expect(createHeader("long enough passphrase", "1234", IT)).rejects.toThrow();
	});
	test("re-wrap with new password keeps vault key", async () => {
		const { vaultKey } = await createHeader("long enough passphrase", undefined, IT);
		const next = await wrapWithSecret("another long passphrase", vaultKey, IT);
		expect(timingSafeEqual(await unwrapWithSecret("another long passphrase", next.kdf, next.wrapped), vaultKey)).toBe(true);
	});
});

describe("entries", () => {
	const entry: Entry = {
		id: "a1",
		type: "totp",
		issuer: "Example",
		account: "alice",
		secret: "JBSWY3DPEHPK3PXP",
		algorithm: "SHA1",
		digits: 6,
		period: 30,
		counter: 0,
		note: "",
		createdAt: 1,
		updatedAt: 1,
	};
	test("seal/open round-trip; revision increments", async () => {
		const { vaultKey } = await createHeader("long enough passphrase", undefined, IT);
		const key = await importAesKey(vaultKey);
		const r1 = await sealEntry(key, entry);
		const r2 = await sealEntry(key, entry, r1);
		expect(r1.revision).toBe(1);
		expect(r2.revision).toBe(2);
		expect(await openEntry(key, r2)).toEqual(entry);
	});
	test("record swapped to another id fails", async () => {
		const { vaultKey } = await createHeader("long enough passphrase", undefined, IT);
		const key = await importAesKey(vaultKey);
		const r = await sealEntry(key, entry);
		await expect(openEntry(key, { ...r, id: "b2" })).rejects.toBeInstanceOf(DecryptError);
		expect(entryAad("x")).toBe("tumbler/entry/v1/x");
	});
});

test("formatCode", () => {
	expect(formatCode("123456")).toBe("123 456");
	expect(formatCode("12345678")).toBe("1234 5678");
	expect(formatCode("1234567")).toBe("1234 567");
	expect(formatCode("12345")).toBe("123 45");
});
