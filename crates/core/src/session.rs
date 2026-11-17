//! Port of `packages/server-kit/src/session.ts`: opaque session tokens in an HttpOnly cookie.
//! The database stores only base64(SHA-256(token)).

use crate::crypto::{random_bytes, random_uuid, sha256, to_b64, to_b64url};
use crate::db::{Db, DbExt, RowExt, q};
use crate::http::R;

pub const SESSION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Extend a session's expiry at most once per this interval, to limit writes.
const SLIDE_EVERY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct SessionRow {
	pub id: String,
	pub user_id: String,
	pub expires_at: i64,
	pub last_seen_at: i64,
}

fn hash_token(token: &str) -> String {
	to_b64(&sha256(token.as_bytes()))
}

/// Returns (id, token).
pub async fn create_session(db: &impl Db, user_id: &str, now: i64) -> R<(String, String)> {
	let token = to_b64url(&random_bytes(32));
	let id = random_uuid();
	db.run(
		q("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)")
			.b(&id)
			.b(user_id)
			.b(hash_token(&token))
			.b(now)
			.b(now + SESSION_TTL_MS)
			.b(now),
	)
	.await?;
	Ok((id, token))
}

fn valid_token(t: &str) -> bool {
	t.len() == 43 && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub async fn find_session(db: &impl Db, token: &str, now: i64) -> R<Option<SessionRow>> {
	if !valid_token(token) {
		return Ok(None);
	}
	let Some(row) =
		db.first(q("SELECT id, user_id, expires_at, last_seen_at FROM sessions WHERE token_hash = ?").b(hash_token(token))).await?
	else {
		return Ok(None);
	};
	let s = SessionRow { id: row.s("id"), user_id: row.s("user_id"), expires_at: row.i("expires_at"), last_seen_at: row.i("last_seen_at") };
	if s.expires_at <= now {
		db.run(q("DELETE FROM sessions WHERE id = ?").b(&s.id)).await?;
		return Ok(None);
	}
	if now - s.last_seen_at > SLIDE_EVERY_MS {
		db.run(q("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?").b(now).b(now + SESSION_TTL_MS).b(&s.id)).await?;
	}
	Ok(Some(s))
}

pub async fn delete_session(db: &impl Db, id: &str) -> R<()> {
	db.run(q("DELETE FROM sessions WHERE id = ?").b(id)).await?;
	Ok(())
}

/// Sign out everywhere else, e.g. after a password change.
pub async fn delete_other_sessions(db: &impl Db, user_id: &str, keep_id: &str) -> R<()> {
	db.run(q("DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?").b(user_id).b(keep_id)).await?;
	Ok(())
}

pub fn session_cookie(token: &str, name: &str) -> String {
	format!("{name}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", SESSION_TTL_MS / 1000)
}

pub fn clear_session_cookie(name: &str) -> String {
	format!("{name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

pub fn read_session_cookie(header: Option<&str>, name: &str) -> Option<String> {
	let header = header.filter(|h| !h.is_empty())?;
	for part in header.split(';') {
		let mut kv = part.trim().splitn(2, '=');
		if kv.next() == Some(name) {
			return Some(kv.next().unwrap_or("").to_string());
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cookies() {
		let h = Some("a=1; __Host-tumbler_session=abc=def; b=2");
		assert_eq!(read_session_cookie(h, "__Host-tumbler_session").as_deref(), Some("abc=def"));
		assert_eq!(read_session_cookie(h, "x"), None);
		assert_eq!(read_session_cookie(Some("__Host-x"), "__Host-x").as_deref(), Some(""));
		assert_eq!(session_cookie("t", "__Host-c"), "__Host-c=t; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000");
	}

	#[test]
	fn token_hash_matches_ts() {
		// toB64(sha256(utf8("abc")))
		assert_eq!(hash_token("abc"), "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
	}
}
