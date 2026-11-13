import { describe, expect, test } from "bun:test";
import {
	DecryptError,
	deriveKeys,
	deriveRootKey,
	fromB64,
	generateVaultKey,
	importAesKey,
	newKdfParams,
	openJSON,
	sealJSON,
	timingSafeEqual,
	toB64,
	unwrapVaultKey,
	wrapVaultKey,
	type KdfParams,
} from "../src/index.ts";

// Low iteration count keeps tests fast; production default is 600k.
const fast = (): KdfParams => newKdfParams(1000);

describe("encoding", () => {
	test("base64 round-trip, large input", () => {
		const bytes = crypto.getRandomValues(new Uint8Array(100_000));
		expect(timingSafeEqual(fromB64(toB64(bytes)), bytes)).toBe(true);
	});
});

describe("kdf", () => {
	test("PBKDF2-SHA256 known answer (RFC 7914 §11 input, 1 iteration)", async () => {
		// PBKDF2-HMAC-SHA256(P="passwd", S="salt", c=1, dkLen=64) first 32 bytes.
		const root = await deriveRootKey("passwd", { alg: "pbkdf2-sha256", iterations: 1, salt: toB64(new TextEncoder().encode("salt")) });
		expect(Buffer.from(root).toString("hex")).toBe("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc");
	});
	test("deterministic for same password and salt; differs otherwise", async () => {
		const p = fast();
		const a = await deriveKeys("correct horse battery staple", p);
		const b = await deriveKeys("correct horse battery staple", p);
		const c = await deriveKeys("correct horse battery stapler", p);
		expect(timingSafeEqual(a.authKey, b.authKey)).toBe(true);
		expect(timingSafeEqual(a.authKey, c.authKey)).toBe(false);
	});
	test("NFKC normalization", async () => {
		const p = fast();
		const a = await deriveKeys("café", p);
		const b = await deriveKeys("café", p);
		expect(timingSafeEqual(a.authKey, b.authKey)).toBe(true);
	});
});

describe("vault key wrap", () => {
	test("wrap/unwrap round-trip", async () => {
		const p = fast();
		const vk = generateVaultKey();
		const { wrapKey } = await deriveKeys("pw-one-long-enough", p);
		const wrapped = await wrapVaultKey(wrapKey, vk);
		expect(timingSafeEqual(await unwrapVaultKey(wrapKey, wrapped), vk)).toBe(true);
	});
	test("wrong password fails with DecryptError", async () => {
		const p = fast();
		const { wrapKey } = await deriveKeys("right", p);
		const wrapped = await wrapVaultKey(wrapKey, generateVaultKey());
		const wrong = await deriveKeys("wrong", p);
		await expect(unwrapVaultKey(wrong.wrapKey, wrapped)).rejects.toBeInstanceOf(DecryptError);
	});
});

describe("aead", () => {
	test("JSON round-trip with AAD; AAD mismatch fails", async () => {
		const key = await importAesKey(generateVaultKey());
		const sealed = await sealJSON(key, { a: 1, s: "secret" }, "entry/1");
		expect(await openJSON(key, sealed, "entry/1")).toEqual({ a: 1, s: "secret" });
		await expect(openJSON(key, sealed, "entry/2")).rejects.toBeInstanceOf(DecryptError);
	});
	test("fresh IV per seal", async () => {
		const key = await importAesKey(generateVaultKey());
		const a = await sealJSON(key, "x");
		const b = await sealJSON(key, "x");
		expect(a.iv).not.toBe(b.iv);
		expect(a.ct).not.toBe(b.ct);
	});
});
