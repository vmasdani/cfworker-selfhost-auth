//! Port of `packages/crypto` (server-side parts): base64, SHA-256, HMAC, HKDF, AES-256-GCM, randomness.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `atob`-compatible decoding: standard alphabet, padding optional, non-zero trailing bits allowed.
const B64_LENIENT: GeneralPurpose = GeneralPurpose::new(
	&alphabet::STANDARD,
	GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true).with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const B64URL: GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Ciphertext envelope `{iv, ct}`, both base64. Field order matches `JSON.stringify` of the TS objects.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sealed {
	pub iv: String,
	pub ct: String,
}

#[derive(Debug)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("Decryption failed: wrong key or corrupted data")
	}
}

pub fn to_b64(b: &[u8]) -> String {
	base64::engine::general_purpose::STANDARD.encode(b)
}

/// Lenient like `atob`; invalid input decodes to an empty vector (callers validate first).
pub fn from_b64(s: &str) -> Vec<u8> {
	B64_LENIENT.decode(s).unwrap_or_default()
}

pub fn to_b64url(b: &[u8]) -> String {
	B64URL.encode(b)
}

pub fn random_bytes(n: usize) -> Vec<u8> {
	let mut v = vec![0u8; n];
	getrandom::getrandom(&mut v).expect("system randomness unavailable");
	v
}

/// `crypto.randomUUID()`: lowercase RFC 4122 version 4.
pub fn random_uuid() -> String {
	let mut b = random_bytes(16);
	b[6] = (b[6] & 0x0f) | 0x40;
	b[8] = (b[8] & 0x3f) | 0x80;
	let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
	format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
	Sha256::digest(data).into()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
	let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
	m.update(data);
	m.finalize().into_bytes().into()
}

/// HKDF-SHA256 with a zero salt, 32 bytes out (`hkdf(root, info)` in `packages/crypto/src/kdf.ts`).
pub fn hkdf32(ikm: &[u8], info: &str) -> [u8; 32] {
	let mut out = [0u8; 32];
	hkdf::Hkdf::<Sha256>::new(Some(&[0u8; 32]), ikm).expand(info.as_bytes(), &mut out).expect("32 bytes is a valid HKDF length");
	out
}

/// Constant-time comparison of equal-length byte slices.
pub fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}
	a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// AES-256-GCM with a random 96-bit IV; `ct` is ciphertext followed by the 16-byte tag (WebCrypto layout).
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &str) -> Sealed {
	let iv = random_bytes(12);
	let ct = Aes256Gcm::new(key.into())
		.encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad: aad.as_bytes() })
		.expect("AES-GCM encryption cannot fail for valid sizes");
	Sealed { iv: to_b64(&iv), ct: to_b64(&ct) }
}

pub fn open(key: &[u8; 32], sealed: &Sealed, aad: &str) -> Result<Vec<u8>, DecryptError> {
	let iv = from_b64(&sealed.iv);
	if iv.len() != 12 {
		return Err(DecryptError);
	}
	Aes256Gcm::new(key.into())
		.decrypt(Nonce::from_slice(&iv), Payload { msg: &from_b64(&sealed.ct), aad: aad.as_bytes() })
		.map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hkdf_rfc5869_case3() {
		// RFC 5869 A.3: zero-length salt equals a HashLen zero salt; info is empty.
		let ikm = [0x0bu8; 22];
		let okm = hkdf32(&ikm, "");
		assert_eq!(to_hex(&okm[..]), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d");
	}

	#[test]
	fn hmac_rfc4231_case2() {
		let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
		assert_eq!(to_hex(&mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	}

	#[test]
	fn seal_roundtrip_and_aad() {
		let key = [7u8; 32];
		let s = seal(&key, b"hello", "a/b");
		assert_eq!(open(&key, &s, "a/b").unwrap(), b"hello");
		assert!(open(&key, &s, "a/c").is_err());
		assert_eq!(from_b64(&s.iv).len(), 12);
		assert_eq!(from_b64(&s.ct).len(), 5 + 16);
	}

	#[test]
	fn uuid_shape() {
		let u = random_uuid();
		assert_eq!(u.len(), 36);
		assert_eq!(&u[14..15], "4");
		assert!("89ab".contains(&u[19..20]));
	}

	#[test]
	fn b64_lenient() {
		assert_eq!(from_b64("aGk="), b"hi");
		assert_eq!(from_b64("aGk"), b"hi");
		assert_eq!(to_b64url(&[0xfb, 0xff]), "-_8");
	}

	fn to_hex(b: &[u8]) -> String {
		b.iter().map(|x| format!("{x:02x}")).collect()
	}
}
