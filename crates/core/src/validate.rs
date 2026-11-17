//! Port of `packages/server-kit/src/validate.ts`: request body validators with the same error codes
//! and messages. Lengths are UTF-16 code units, as in JavaScript.

use crate::crypto::{Sealed, sha256};
use crate::http::{R, bad_msg, err};
use crate::text::{js_len, js_trim};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type Obj = Map<String, Value>;

const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

fn get<'a>(o: &'a Obj, k: &str) -> &'a Value {
	o.get(k).unwrap_or(&Value::Null)
}

/// Parses a JSON request body that must be an object (`body(c)` in worker-accounts).
pub fn body(raw: &[u8]) -> R<Obj> {
	match serde_json::from_slice::<Value>(raw) {
		Ok(Value::Object(o)) => Ok(o),
		_ => Err(err(400, "invalid_json")),
	}
}

pub fn obj<'a>(v: &'a Value, what: &str) -> R<&'a Obj> {
	v.as_object().ok_or_else(|| bad_msg("invalid_request", &format!("{what} must be an object")))
}

pub fn obj_field<'a>(o: &'a Obj, k: &str) -> R<&'a Obj> {
	obj(get(o, k), k)
}

pub fn str_range(o: &Obj, k: &str, min: usize, max: usize) -> R<String> {
	match get(o, k) {
		Value::String(s) if (min..=max).contains(&js_len(s)) => Ok(s.clone()),
		_ => Err(bad_msg("invalid_request", &format!("{k} must be a string"))),
	}
}

pub fn str_max(o: &Obj, k: &str, max: usize) -> R<String> {
	str_range(o, k, 0, max)
}

pub fn opt_str(o: &Obj, k: &str, max: usize) -> R<Option<String>> {
	match get(o, k) {
		Value::Null => Ok(None),
		_ => str_max(o, k, max).map(Some),
	}
}

/// A JSON number that is a safe integer (`Number.isSafeInteger`), in `[min, max]`.
pub fn int(o: &Obj, k: &str, min: i64, max: i64) -> R<i64> {
	let v = match get(o, k) {
		Value::Number(n) => n
			.as_i64()
			.filter(|i| (i.unsigned_abs() as f64) <= MAX_SAFE)
			.or_else(|| n.as_f64().filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE).map(|f| f as i64)),
		_ => None,
	};
	match v {
		Some(i) if i >= min && i <= max => Ok(i),
		_ => Err(bad_msg("invalid_request", &format!("{k} must be an integer"))),
	}
}

pub fn boolean(o: &Obj, k: &str) -> R<bool> {
	get(o, k).as_bool().ok_or_else(|| bad_msg("invalid_request", &format!("{k} must be a boolean")))
}

fn is_b64(v: &str) -> bool {
	let body = v.trim_end_matches('=');
	v.len() - body.len() <= 2 && body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
}

/// Base64 string (standard alphabet, padded), optionally of an exact decoded length.
pub fn b64(o: &Obj, k: &str, bytes: Option<usize>, max: usize) -> R<String> {
	let v = str_max(o, k, max)?;
	if !is_b64(&v) || v.len() % 4 != 0 {
		return Err(bad_msg("invalid_request", &format!("{k} must be base64")));
	}
	if let Some(n) = bytes {
		let pad = v.len() - v.trim_end_matches('=').len();
		if v.len() * 3 / 4 - pad != n {
			return Err(bad_msg("invalid_request", &format!("{k} must be {n} bytes")));
		}
	}
	Ok(v)
}

pub fn b64_bytes(o: &Obj, k: &str, bytes: usize) -> R<String> {
	b64(o, k, Some(bytes), 65536)
}

pub fn sealed(o: &Obj, k: &str, max: usize, allow_empty: bool) -> R<Sealed> {
	let s = obj_field(o, k)?;
	let empty = |f: &str| allow_empty && get(s, f).as_str() == Some("");
	let iv = if empty("iv") { String::new() } else { b64(s, "iv", Some(12), 65536)? };
	let ct = if empty("ct") { String::new() } else { b64(s, "ct", None, max)? };
	Ok(Sealed { iv, ct })
}

pub const MIN_KDF_ITERATIONS: i64 = 100_000;
pub const MAX_KDF_ITERATIONS: i64 = 10_000_000;
pub const DEFAULT_PBKDF2_ITERATIONS: i64 = 600_000;

/// Field order matches the TS object, so `JSON.stringify` output is identical.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
	pub alg: String,
	pub iterations: i64,
	pub salt: String,
}

pub fn kdf(o: &Obj) -> R<KdfParams> {
	let p = obj_field(o, "kdf")?;
	if get(p, "alg").as_str() != Some("pbkdf2-sha256") {
		return Err(bad_msg("invalid_request", "Unsupported KDF"));
	}
	Ok(KdfParams {
		alg: "pbkdf2-sha256".into(),
		iterations: int(p, "iterations", MIN_KDF_ITERATIONS, MAX_KDF_ITERATIONS)?,
		salt: b64(p, "salt", Some(16), 65536)?,
	})
}

pub struct PasswordMaterial {
	pub kdf: KdfParams,
	pub auth_key: String,
	pub wrapped_vault_key: Sealed,
}

pub struct AccountMaterial {
	pub pw: PasswordMaterial,
	pub recovery_wrapped_key: Sealed,
	pub recovery_auth_key: String,
}

pub fn password_material(o: &Obj) -> R<PasswordMaterial> {
	Ok(PasswordMaterial {
		kdf: kdf(o)?,
		auth_key: b64_bytes(o, "authKey", 32)?,
		wrapped_vault_key: sealed(o, "wrappedVaultKey", 256, false)?,
	})
}

pub fn account_material(o: &Obj) -> R<AccountMaterial> {
	Ok(AccountMaterial {
		pw: password_material(o)?,
		recovery_wrapped_key: sealed(o, "recoveryWrappedKey", 256, false)?,
		recovery_auth_key: b64_bytes(o, "recoveryAuthKey", 32)?,
	})
}

/// `^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])$`
fn valid_username(u: &str) -> bool {
	let b = u.as_bytes();
	let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
	(3..=64).contains(&b.len())
		&& edge(b[0])
		&& edge(b[b.len() - 1])
		&& b[1..b.len() - 1].iter().all(|&c| edge(c) || c == b'.' || c == b'_' || c == b'-')
}

pub fn normalize_username(v: &str) -> String {
	js_trim(v).to_lowercase()
}

pub fn username(o: &Obj, k: &str) -> R<String> {
	let u = normalize_username(&str_max(o, k, 64)?);
	if !valid_username(&u) {
		return Err(bad_msg("invalid_username", "Username: 3–64 characters, a–z, 0–9, '.', '_' or '-'"));
	}
	Ok(u)
}

/// Constant-time string comparison (hashes both sides first so lengths do not leak).
pub fn timing_safe_eq_strings(a: &str, b: &str) -> bool {
	crate::crypto::timing_safe_eq(&sha256(a.as_bytes()), &sha256(b.as_bytes()))
}

/// Checks a string against a character class and length range (replaces the small TS regexes).
pub fn chars_in(s: &str, min: usize, max: usize, ok: impl Fn(u8) -> bool) -> bool {
	(min..=max).contains(&s.len()) && s.bytes().all(ok)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn o(v: Value) -> Obj {
		v.as_object().unwrap().clone()
	}

	#[test]
	fn ints_follow_number_is_safe_integer() {
		let b = o(json!({ "a": 5, "b": 5.0, "c": 5.5, "d": "5", "e": 9007199254740992u64 }));
		assert_eq!(int(&b, "a", 0, 10).unwrap(), 5);
		assert_eq!(int(&b, "b", 0, 10).unwrap(), 5);
		assert!(int(&b, "c", 0, 10).is_err());
		assert!(int(&b, "d", 0, 10).is_err());
		assert!(int(&b, "e", 0, i64::MAX).is_err());
	}

	#[test]
	fn base64_rules() {
		let b = o(json!({ "k": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "bad": "AAA", "pad": "AA==" }));
		assert!(b64(&b, "k", Some(32), 65536).is_ok());
		assert!(b64(&b, "k", Some(31), 65536).is_err());
		assert!(b64(&b, "bad", None, 65536).is_err());
		assert_eq!(b64(&b, "pad", Some(1), 65536).unwrap(), "AA==");
	}

	#[test]
	fn usernames() {
		let ok = |u: &str| username(&o(json!({ "username": u })), "username").ok();
		assert_eq!(ok(" Alice ").as_deref(), Some("alice"));
		assert_eq!(ok("a.b").as_deref(), Some("a.b"));
		assert!(ok("ab").is_none());
		assert!(ok(".ab").is_none());
		assert!(ok("ab-").is_none());
		assert!(ok("a b").is_none());
	}

	#[test]
	fn optional_strings() {
		let b = o(json!({ "n": null, "s": "x", "i": 1 }));
		assert_eq!(opt_str(&b, "missing", 16).unwrap(), None);
		assert_eq!(opt_str(&b, "n", 16).unwrap(), None);
		assert_eq!(opt_str(&b, "s", 16).unwrap().as_deref(), Some("x"));
		assert!(opt_str(&b, "i", 16).is_err());
	}
}
