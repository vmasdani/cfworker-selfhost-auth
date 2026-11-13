import { describe, expect, test } from "bun:test";
import {
	base32Decode,
	base32Encode,
	formatOtpauthUri,
	hotp,
	importOtpKey,
	OtpauthError,
	parseOtpauthUri,
	totp,
	totpRemainingMs,
	type OtpAlgorithm,
} from "../src/index.ts";

const ascii = (s: string) => new TextEncoder().encode(s);

describe("base32 (RFC 4648 §10 vectors)", () => {
	const vectors: [string, string][] = [
		["", ""],
		["f", "MY======"],
		["fo", "MZXQ===="],
		["foo", "MZXW6==="],
		["foob", "MZXW6YQ="],
		["fooba", "MZXW6YTB"],
		["foobar", "MZXW6YTBOI======"],
	];
	for (const [plain, encoded] of vectors) {
		test(JSON.stringify(plain), () => {
			expect(base32Encode(ascii(plain))).toBe(encoded);
			expect(new TextDecoder().decode(base32Decode(encoded))).toBe(plain);
		});
	}
	test("tolerates lowercase, spaces, dashes, missing padding", () => {
		expect(new TextDecoder().decode(base32Decode("mzxw 6ytb-oi"))).toBe("foobar");
	});
	test("rejects invalid characters", () => {
		expect(() => base32Decode("MZXW1")).toThrow();
	});
});

describe("HOTP (RFC 4226 Appendix D)", () => {
	const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
	test("counters 0–9", async () => {
		const key = await importOtpKey(ascii("12345678901234567890"));
		for (let i = 0; i < expected.length; i++) expect(await hotp(key, i)).toBe(expected[i]!);
	});
});

describe("TOTP (RFC 6238 Appendix B)", () => {
	const secrets: Record<OtpAlgorithm, string> = {
		SHA1: "12345678901234567890",
		SHA256: "12345678901234567890123456789012",
		SHA512: "1234567890123456789012345678901234567890123456789012345678901234",
	};
	const vectors: [number, OtpAlgorithm, string][] = [
		[59, "SHA1", "94287082"],
		[59, "SHA256", "46119246"],
		[59, "SHA512", "90693936"],
		[1111111109, "SHA1", "07081804"],
		[1111111109, "SHA256", "68084774"],
		[1111111109, "SHA512", "25091201"],
		[1111111111, "SHA1", "14050471"],
		[1111111111, "SHA256", "67062674"],
		[1111111111, "SHA512", "99943326"],
		[1234567890, "SHA1", "89005924"],
		[1234567890, "SHA256", "91819424"],
		[1234567890, "SHA512", "93441116"],
		[2000000000, "SHA1", "69279037"],
		[2000000000, "SHA256", "90698825"],
		[2000000000, "SHA512", "38618901"],
		[20000000000, "SHA1", "65353130"],
		[20000000000, "SHA256", "77737706"],
		[20000000000, "SHA512", "47863826"],
	];
	for (const [t, alg, code] of vectors) {
		test(`${alg} T=${t}`, async () => {
			const key = await importOtpKey(ascii(secrets[alg]), alg);
			expect(await totp(key, t * 1000, { digits: 8 })).toBe(code);
		});
	}
	test("remaining time", () => {
		expect(totpRemainingMs(0)).toBe(30_000);
		expect(totpRemainingMs(29_500)).toBe(500);
		expect(totpRemainingMs(30_000)).toBe(30_000);
	});
});

describe("otpauth URI", () => {
	test("parses full URI", () => {
		const p = parseOtpauthUri(
			"otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
		);
		expect(p).toEqual({
			type: "totp",
			issuer: "ACME Co",
			account: "john.doe@email.com",
			secret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			algorithm: "SHA256",
			digits: 8,
			period: 60,
			counter: 0,
		});
	});
	test("defaults and label-only issuer", () => {
		const p = parseOtpauthUri("otpauth://totp/Example:alice?secret=jbsw y3dp ehpk 3pxp");
		expect(p.issuer).toBe("Example");
		expect(p.account).toBe("alice");
		expect(p.secret).toBe("JBSWY3DPEHPK3PXP");
		expect([p.algorithm, p.digits, p.period]).toEqual(["SHA1", 6, 30]);
	});
	test("issuer param wins over label prefix", () => {
		expect(parseOtpauthUri("otpauth://totp/Old:bob?secret=JBSWY3DPEHPK3PXP&issuer=New").issuer).toBe("New");
	});
	test("hotp requires counter", () => {
		expect(() => parseOtpauthUri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")).toThrow(OtpauthError);
		expect(parseOtpauthUri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=7").counter).toBe(7);
	});
	test("rejects bad input", () => {
		expect(() => parseOtpauthUri("https://example.com")).toThrow(OtpauthError);
		expect(() => parseOtpauthUri("otpauth://totp/x")).toThrow(OtpauthError);
		expect(() => parseOtpauthUri("otpauth://totp/x?secret=!!!")).toThrow(OtpauthError);
		expect(() => parseOtpauthUri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=2")).toThrow(OtpauthError);
		expect(() => parseOtpauthUri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")).toThrow(OtpauthError);
	});
	test("format round-trips", () => {
		const p = parseOtpauthUri("otpauth://totp/My%20Bank:me%40x.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Bank");
		expect(parseOtpauthUri(formatOtpauthUri(p))).toEqual(p);
		const h = parseOtpauthUri("otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=3");
		expect(parseOtpauthUri(formatOtpauthUri(h))).toEqual(h);
	});
});
