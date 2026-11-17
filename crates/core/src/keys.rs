//! Port of `packages/server-kit/src/server-secret.ts`: keys derived from SERVER_SECRET, one HKDF subkey
//! per purpose. Same info strings, so verifiers and sealed secrets are interchangeable with the TS code.

use crate::crypto::{DecryptError, Sealed, from_b64, hkdf32, hmac_sha256, open, seal, timing_safe_eq, to_b64};

#[derive(Clone)]
pub struct ServerKeys {
	verifier_key: [u8; 32],
	decoy_key: [u8; 32],
	seal_key: [u8; 32],
}

impl ServerKeys {
	/// Fails like the TS code when the secret is missing or shorter than 32 characters.
	pub fn new(secret: &str) -> Result<ServerKeys, String> {
		if crate::text::js_len(secret) < 32 {
			return Err("SERVER_SECRET is missing or shorter than 32 characters".into());
		}
		let ikm = secret.as_bytes();
		Ok(ServerKeys {
			verifier_key: hkdf32(ikm, "cfsa/server/v1/auth-verifier"),
			decoy_key: hkdf32(ikm, "cfsa/server/v1/decoy-salt"),
			seal_key: hkdf32(ikm, "cfsa/server/v1/seal"),
		})
	}

	/// HMAC of a client auth key (base64 in, base64 out): what the database stores instead of the key.
	pub fn verifier(&self, auth_key_b64: &str) -> String {
		to_b64(&hmac_sha256(&self.verifier_key, &from_b64(auth_key_b64)))
	}

	pub fn verify(&self, auth_key_b64: &str, stored: &str) -> bool {
		timing_safe_eq(&from_b64(&self.verifier(auth_key_b64)), &from_b64(stored))
	}

	/// Deterministic fake salt for unknown usernames, so pre-login does not reveal which exist.
	pub fn decoy_salt(&self, username: &str) -> String {
		to_b64(&hmac_sha256(&self.decoy_key, username.as_bytes())[..16])
	}

	pub fn seal_secret(&self, plaintext: &str, aad: &str) -> Sealed {
		seal(&self.seal_key, plaintext.as_bytes(), aad)
	}

	pub fn open_secret(&self, sealed: &Sealed, aad: &str) -> Result<String, DecryptError> {
		String::from_utf8(open(&self.seal_key, sealed, aad)?).map_err(|_| DecryptError)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rejects_short_secret() {
		assert!(ServerKeys::new("short").is_err());
	}

	#[test]
	fn verifier_roundtrip() {
		let k = ServerKeys::new("0123456789abcdef0123456789abcdef").unwrap();
		let key = to_b64(&[1u8; 32]);
		let v = k.verifier(&key);
		assert!(k.verify(&key, &v));
		assert!(!k.verify(&to_b64(&[2u8; 32]), &v));
		assert_eq!(crate::crypto::from_b64(&k.decoy_salt("bob")).len(), 16);
		let s = k.seal_secret("JBSWY3DP", "tumbler/login-totp/v1/x");
		assert_eq!(k.open_secret(&s, "tumbler/login-totp/v1/x").unwrap(), "JBSWY3DP");
	}
}
