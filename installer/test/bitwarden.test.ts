import { describe, expect, test } from "bun:test";
import {
	decryptEncString,
	deriveMasterKeys,
	hkdfExpand,
	makeRegistration,
	splitKey,
	unb64,
} from "../src/lib/bitwarden.ts";
import { validateMasterPassword } from "../src/lib/password.ts";
import { loginFromUsername } from "../src/nodewarden.ts";

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));

describe("HKDF-Expand", () => {
	test("RFC 5869 test case 1 (expand step)", async () => {
		const prk = hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
		const okm = await hkdfExpand(prk, hex("f0f1f2f3f4f5f6f7f8f9"), 42);
		expect(Buffer.from(okm).toString("hex")).toBe(
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		);
	});
});

describe("registration", () => {
	test("email is normalized for salt and body", async () => {
		const a = await deriveMasterKeys(" Admin@Example.COM ", "pw", 1000);
		const b = await deriveMasterKeys("admin@example.com", "pw", 1000);
		expect(a.masterPasswordHash).toBe(b.masterPasswordHash);
	});

	test("body decrypts back to user key and RSA private key", async () => {
		const reg = await makeRegistration({ email: "Admin@Example.com", name: "Admin", password: "pw", iterations: 1000 });
		expect(reg.body.email).toBe("admin@example.com");
		expect(reg.body.kdf).toBe(0);
		expect(reg.body.key.startsWith("2.")).toBe(true);
		const userKey = await decryptEncString(reg.body.key, reg.masterKeys.stretched);
		expect(Buffer.from(userKey).equals(Buffer.from(reg.userKey))).toBe(true);

		const pkcs8 = await decryptEncString(reg.body.keys.encryptedPrivateKey, splitKey(userKey));
		const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["decrypt"]);
		const pub = await crypto.subtle.importKey("spki", unb64(reg.body.keys.publicKey), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
		const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, new TextEncoder().encode("ok"));
		expect(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, ct))).toBe("ok");
	});

	test("tampered EncString is rejected", async () => {
		const reg = await makeRegistration({ email: "a@b.c", name: "a", password: "pw", iterations: 1000 });
		const [head, ct, mac] = reg.body.key.split("|");
		const flipped = `${head}|${ct!.slice(0, -4)}AAAA|${mac}`;
		await expect(decryptEncString(flipped, reg.masterKeys.stretched)).rejects.toThrow();
	});
});

test("master password validation", () => {
	expect(validateMasterPassword("short", "a@b.c")).not.toBeNull();
	expect(validateMasterPassword("aaaaaaaaaaaaaa", "a@b.c")).not.toBeNull();
	expect(validateMasterPassword(" padded passphrase ", "a@b.c")).not.toBeNull();
	expect(validateMasterPassword("vmasdani rocks hard", "vmasdani@proton.me")).not.toBeNull();
	expect(validateMasterPassword("orbit tulip cactus marble", "vmasdani@proton.me")).toBeNull();
});

describe("loginFromUsername", () => {
	test("plain username gets the worker host", () => {
		expect(loginFromUsername("Admin", "https://nodewarden.me.workers.dev")).toBe("admin@nodewarden.me.workers.dev");
	});
	test("local / IP hosts fall back to nodewarden.local", () => {
		expect(loginFromUsername("admin", "http://127.0.0.1:8787")).toBe("admin@nodewarden.local");
		expect(loginFromUsername("admin", "http://localhost:8787")).toBe("admin@nodewarden.local");
	});
	test("email is kept, lowercased", () => {
		expect(loginFromUsername(" Me@Example.com ", "https://x.workers.dev")).toBe("me@example.com");
	});
	test("rejects bad input", () => {
		expect(() => loginFromUsername("bad name", "https://x.dev")).toThrow();
		expect(() => loginFromUsername("-admin", "https://x.dev")).toThrow();
		expect(() => loginFromUsername("me@nodot", "https://x.dev")).toThrow();
	});
});
