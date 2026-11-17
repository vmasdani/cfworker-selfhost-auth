//! Validation and access checks shared by Coffer routes (port of `worker/common.ts`).

use cfsa_core::accounts::Ctx;
use cfsa_core::crypto::Sealed;
use cfsa_core::db::{Db, DbExt, RowExt, q};
use cfsa_core::http::{R, bad, bad_msg, err, err_msg};
use cfsa_core::text::js_trim;
use cfsa_core::validate::{self as v, Obj};
use serde_json::{Value, json};

/// Max base64 ciphertext of one secret (about 48 KB of plaintext).
pub const MAX_SECRET_CT: usize = 65_536;

fn hex_lower(c: u8) -> bool {
	c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
pub fn is_uuid(s: &str) -> bool {
	let b = s.as_bytes();
	b.len() == 36 && b.iter().enumerate().all(|(i, &c)| if matches!(i, 8 | 13 | 18 | 23) { c == b'-' } else { hex_lower(c) })
}

/// `^[0-9a-f]{64}$`
pub fn is_mac(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(hex_lower)
}

/// `^cfi_[A-Za-z0-9_-]{22}$`
pub fn is_client_id(s: &str) -> bool {
	s.len() == 26 && s.starts_with("cfi_") && s.bytes().skip(4).all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// `^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`
fn is_env_name(s: &str) -> bool {
	let b = s.as_bytes();
	(1..=32).contains(&b.len())
		&& b[0].is_ascii_alphanumeric()
		&& b[1..].iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-')
}

pub fn uuid(o: &Obj, k: &str) -> R<String> {
	let s = v::str_max(o, k, 36)?;
	if !is_uuid(&s) {
		return Err(bad_msg("invalid_request", &format!("{k} must be a lowercase UUID")));
	}
	Ok(s)
}

/// A path parameter; 404 when it does not match.
pub fn param(s: &str, ok: fn(&str) -> bool) -> R<&str> {
	if ok(s) { Ok(s) } else { Err(err(404, "not_found")) }
}

pub fn project_name(o: &Obj) -> R<String> {
	let s = v::str_max(o, "name", 64)?;
	let t = js_trim(&s);
	if t.is_empty() {
		return Err(bad_msg("invalid_name", "Name is required"));
	}
	Ok(t.to_string())
}

pub fn env_name(o: &Obj) -> R<String> {
	let s = v::str_max(o, "name", 32)?;
	let t = js_trim(&s);
	if !is_env_name(t) {
		return Err(bad_msg("invalid_name", "Environment name: 1–32 characters, letters, digits, '.', '_' or '-'"));
	}
	Ok(t.to_string())
}

/// `{iv, ct}` sealed with AES-GCM.
pub fn sealed_key(o: &Obj, k: &str) -> R<Sealed> {
	v::sealed(o, k, 256, false)
}

/// Project key wrapped to a member's public key: `{epk, iv, ct}`.
pub fn member_wrap(o: &Obj, k: &str) -> R<Value> {
	let w = v::obj_field(o, k)?;
	let epk = v::b64(w, "epk", None, 256)?;
	let s = v::sealed(o, k, 256, false)?;
	Ok(json!({ "epk": epk, "iv": s.iv, "ct": s.ct }))
}

pub fn role(o: &Obj) -> R<String> {
	let r = if o.contains_key("role") { v::str_max(o, "role", 8)? } else { "member".into() };
	if r != "owner" && r != "member" {
		return Err(bad("invalid_role"));
	}
	Ok(r)
}

pub struct Membership {
	pub project_id: String,
	pub role: String,
}

/// The signed-in user's membership; 404 when not a member, so project IDs do not leak.
pub async fn membership<D: Db>(c: &Ctx<'_, D>, project_id: &str, need_owner: bool) -> R<Membership> {
	let row =
		c.db.first(q("SELECT role FROM project_members WHERE project_id = ? AND user_id = ?").b(project_id).b(&c.user().id))
			.await?
			.ok_or_else(|| err(404, "not_found"))?;
	let role = row.s("role");
	if need_owner && role != "owner" {
		return Err(err_msg(403, "owner_only", "Only project owners can do this"));
	}
	Ok(Membership { project_id: project_id.to_string(), role })
}

pub async fn env_membership<D: Db>(c: &Ctx<'_, D>, env_id: &str) -> R<Membership> {
	let row =
		c.db.first(
			q("SELECT e.project_id AS projectId, m.role FROM environments e
			 JOIN project_members m ON m.project_id = e.project_id AND m.user_id = ?
			 WHERE e.id = ?")
			.b(&c.user().id)
			.b(env_id),
		)
		.await?
		.ok_or_else(|| err(404, "not_found"))?;
	Ok(Membership { project_id: row.s("projectId"), role: row.s("role") })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn patterns() {
		assert!(is_uuid("0f8b2c1e-8a3b-4c5d-9e6f-0123456789ab"));
		assert!(!is_uuid("0F8B2C1E-8A3B-4C5D-9E6F-0123456789AB"));
		assert!(is_mac(&"a".repeat(64)));
		assert!(!is_mac(&"g".repeat(64)));
		assert!(is_client_id("cfi_abcdefghijklmnopqrstu-"));
		assert!(!is_client_id("cfi_abc"));
		assert!(is_env_name("prod.eu-1") && !is_env_name("-x") && !is_env_name(""));
	}
}
