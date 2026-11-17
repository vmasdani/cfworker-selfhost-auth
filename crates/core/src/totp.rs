//! Port of `packages/totp` (server-side parts): RFC 4648 base32, HOTP (RFC 4226), TOTP (RFC 6238),
//! and the otpauth:// URI the login-TOTP setup returns.

use hmac::{Hmac, Mac};
use sha1::Sha1;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, PartialEq)]
pub struct Base32Error;

/// Uppercase, strip whitespace, dashes and trailing padding.
pub fn normalize_base32(input: &str) -> String {
	let s: String = input.to_uppercase().chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
	s.trim_end_matches('=').to_string()
}

pub fn base32_decode(input: &str) -> Result<Vec<u8>, Base32Error> {
	let s = normalize_base32(input);
	let mut out = Vec::with_capacity(s.len() * 5 / 8);
	let (mut bits, mut value) = (0u32, 0u32);
	for c in s.bytes() {
		let v = ALPHABET.iter().position(|&a| a == c).ok_or(Base32Error)? as u32;
		value = (value << 5) | v;
		bits += 5;
		if bits >= 8 {
			bits -= 8;
			out.push(((value >> bits) & 0xff) as u8);
		}
	}
	Ok(out)
}

pub fn base32_encode(bytes: &[u8], padding: bool) -> String {
	let mut out = String::new();
	let (mut bits, mut value) = (0u32, 0u32);
	for &b in bytes {
		value = (value << 8) | b as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			out.push(ALPHABET[((value >> bits) & 31) as usize] as char);
		}
	}
	if bits > 0 {
		out.push(ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
	}
	if padding {
		while !out.len().is_multiple_of(8) {
			out.push('=');
		}
	}
	out
}

/// HOTP with HMAC-SHA1 (the only algorithm login TOTP uses).
pub fn hotp_sha1(secret: &[u8], counter: u64, digits: u32) -> String {
	let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
	m.update(&counter.to_be_bytes());
	let mac = m.finalize().into_bytes();
	let off = (mac[mac.len() - 1] & 0x0f) as usize;
	let bin = ((mac[off] as u32 & 0x7f) << 24) | ((mac[off + 1] as u32) << 16) | ((mac[off + 2] as u32) << 8) | mac[off + 3] as u32;
	format!("{:0width$}", bin % 10u32.pow(digits), width = digits as usize)
}

/// TOTP time step for a Unix time in milliseconds.
pub fn totp_counter(time_ms: i64, period: i64) -> i64 {
	time_ms.div_euclid(1000 * period)
}

/// `formatOtpauthUri` for a TOTP, SHA1, 6 digits, 30 s parameters.
pub fn otpauth_totp_uri(issuer: &str, account: &str, secret: &str) -> String {
	use crate::text::{encode_uri_component as enc, form_encode as form};
	let label = if issuer.is_empty() { enc(account) } else { format!("{}:{}", enc(issuer), enc(account)) };
	let mut q = format!("secret={}", form(&normalize_base32(secret)));
	if !issuer.is_empty() {
		q.push_str(&format!("&issuer={}", form(issuer)));
	}
	q.push_str("&algorithm=SHA1&digits=6&period=30");
	format!("otpauth://totp/{label}?{}", q.replace('+', "%20"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rfc4226_vectors() {
		let key = b"12345678901234567890";
		let want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
		for (i, w) in want.iter().enumerate() {
			assert_eq!(hotp_sha1(key, i as u64, 6), *w);
		}
	}

	#[test]
	fn rfc6238_sha1_vectors() {
		let key = b"12345678901234567890";
		let cases: [(i64, &str); 6] = [
			(59, "94287082"),
			(1111111109, "07081804"),
			(1111111111, "14050471"),
			(1234567890, "89005924"),
			(2000000000, "69279037"),
			(20000000000, "65353130"),
		];
		for (t, want) in cases {
			assert_eq!(hotp_sha1(key, totp_counter(t * 1000, 30) as u64, 8), want, "t={t}");
		}
	}

	#[test]
	fn base32_roundtrip() {
		assert_eq!(base32_encode(b"foobar", true), "MZXW6YTBOI======");
		assert_eq!(base32_encode(b"foobar", false), "MZXW6YTBOI");
		assert_eq!(base32_decode("mzxw 6ytb-oi==").unwrap(), b"foobar");
		assert_eq!(base32_decode("MZ1"), Err(Base32Error));
		let r: Vec<u8> = (0u8..20).collect();
		assert_eq!(base32_decode(&base32_encode(&r, false)).unwrap(), r);
	}

	#[test]
	fn otpauth_matches_ts() {
		// Same output as formatOtpauthUri in packages/totp/src/otpauth.ts.
		assert_eq!(
			otpauth_totp_uri("Tumbler (t.example.com)", "alice", "JBSWY3DPEHPK3PXP"),
			"otpauth://totp/Tumbler%20(t.example.com):alice?secret=JBSWY3DPEHPK3PXP&issuer=Tumbler%20%28t.example.com%29&algorithm=SHA1&digits=6&period=30"
		);
	}
}
