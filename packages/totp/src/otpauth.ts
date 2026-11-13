// otpauth:// Key URI format (https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

import { base32Decode, normalizeBase32 } from "./base32.ts";
import type { OtpAlgorithm } from "./otp.ts";

export type OtpType = "totp" | "hotp";

export interface OtpParams {
	type: OtpType;
	issuer: string;
	account: string;
	/** Normalized base32, no padding. */
	secret: string;
	algorithm: OtpAlgorithm;
	digits: number;
	/** TOTP period in seconds. */
	period: number;
	/** HOTP counter. */
	counter: number;
}

export class OtpauthError extends Error {
	override name = "OtpauthError";
}

export const DEFAULT_OTP: Omit<OtpParams, "issuer" | "account" | "secret"> = {
	type: "totp",
	algorithm: "SHA1",
	digits: 6,
	period: 30,
	counter: 0,
};

export function parseAlgorithm(value: string | null | undefined): OtpAlgorithm {
	if (!value) return "SHA1";
	const v = value.toUpperCase().replace("-", "");
	if (v === "SHA1" || v === "SHA256" || v === "SHA512") return v;
	throw new OtpauthError(`Unsupported algorithm: ${value}`);
}

/** Validate and normalize OTP parameters. Throws OtpauthError. */
export function validateOtpParams(p: OtpParams): OtpParams {
	const secret = normalizeBase32(p.secret);
	if (!secret) throw new OtpauthError("Secret is required");
	let bytes: Uint8Array;
	try {
		bytes = base32Decode(secret);
	} catch {
		throw new OtpauthError("Secret is not valid base32");
	}
	if (bytes.length === 0) throw new OtpauthError("Secret is too short");
	if (p.type !== "totp" && p.type !== "hotp") throw new OtpauthError(`Unsupported type: ${String(p.type)}`);
	if (!Number.isInteger(p.digits) || p.digits < 4 || p.digits > 10) throw new OtpauthError("Digits must be 4–10");
	if (!Number.isInteger(p.period) || p.period < 1 || p.period > 3600) throw new OtpauthError("Period must be 1–3600 s");
	if (!Number.isSafeInteger(p.counter) || p.counter < 0) throw new OtpauthError("Invalid counter");
	return {
		...p,
		secret,
		issuer: p.issuer.trim(),
		account: p.account.trim(),
		algorithm: parseAlgorithm(p.algorithm),
	};
}

function intParam(params: URLSearchParams, name: string, fallback: number): number {
	const raw = params.get(name);
	if (raw === null || raw === "") return fallback;
	if (!/^\d+$/.test(raw)) throw new OtpauthError(`Invalid ${name}: ${raw}`);
	return Number(raw);
}

export function parseOtpauthUri(uri: string): OtpParams {
	let url: URL;
	try {
		url = new URL(uri.trim());
	} catch {
		throw new OtpauthError("Not a valid URI");
	}
	if (url.protocol !== "otpauth:") throw new OtpauthError("Not an otpauth:// URI");
	const type = url.hostname.toLowerCase();
	if (type !== "totp" && type !== "hotp") throw new OtpauthError(`Unsupported type: ${type}`);

	let label: string;
	try {
		label = decodeURIComponent(url.pathname.replace(/^\//, ""));
	} catch {
		throw new OtpauthError("Invalid label encoding");
	}
	let labelIssuer = "";
	let account = label;
	const colon = label.indexOf(":");
	if (colon >= 0) {
		labelIssuer = label.slice(0, colon).trim();
		account = label.slice(colon + 1).trim();
	}

	const q = url.searchParams;
	if (type === "hotp" && !q.has("counter")) throw new OtpauthError("HOTP URI requires counter");
	return validateOtpParams({
		type,
		issuer: q.get("issuer") ?? labelIssuer,
		account,
		secret: q.get("secret") ?? "",
		algorithm: parseAlgorithm(q.get("algorithm")),
		digits: intParam(q, "digits", DEFAULT_OTP.digits),
		period: intParam(q, "period", DEFAULT_OTP.period),
		counter: intParam(q, "counter", DEFAULT_OTP.counter),
	});
}

export function formatOtpauthUri(p: OtpParams): string {
	const label = p.issuer
		? `${encodeURIComponent(p.issuer)}:${encodeURIComponent(p.account)}`
		: encodeURIComponent(p.account);
	const q = new URLSearchParams({ secret: normalizeBase32(p.secret) });
	if (p.issuer) q.set("issuer", p.issuer);
	q.set("algorithm", p.algorithm);
	q.set("digits", String(p.digits));
	if (p.type === "totp") q.set("period", String(p.period));
	else q.set("counter", String(p.counter));
	return `otpauth://${p.type}/${label}?${q.toString().replace(/\+/g, "%20")}`;
}
