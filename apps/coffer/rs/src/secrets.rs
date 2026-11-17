//! Secret rows (port of `worker/secrets.ts`). Shared by the dashboard routes (session) and the machine
//! REST API (client credentials). The server never sees names or values: rows are addressed by
//! name_mac and hold AES-GCM ciphertext.

use crate::common::MAX_SECRET_CT;
use cfsa_core::db::{Db, DbExt, Row, q};
use cfsa_core::http::{Error, R};
use cfsa_core::validate::{self as v, Obj};

const COLUMNS: &str = "name_mac AS mac, iv, ct, version, updated_at AS updatedAt";

pub async fn list_secrets(db: &impl Db, env_id: &str) -> R<Vec<Row>> {
	db.all(q(&format!("SELECT {COLUMNS} FROM secrets WHERE env_id = ? ORDER BY name_mac")).b(env_id)).await
}

pub async fn get_secret(db: &impl Db, env_id: &str, mac: &str) -> R<Option<Row>> {
	db.first(q(&format!("SELECT {COLUMNS} FROM secrets WHERE env_id = ? AND name_mac = ?")).b(env_id).b(mac)).await
}

pub struct SecretBody {
	iv: String,
	ct: String,
}

pub fn secret_body(o: &Obj) -> R<SecretBody> {
	Ok(SecretBody { iv: v::b64(o, "iv", Some(12), 65536)?, ct: v::b64(o, "ct", None, MAX_SECRET_CT)? })
}

/// Insert or replace; the previous version goes to secret_history. One transaction.
pub async fn put_secret(db: &impl Db, env_id: &str, mac: &str, s: &SecretBody, by: &str, now: i64) -> R<Row> {
	db.batch_(vec![
		q("INSERT INTO secret_history (env_id, name_mac, iv, ct, version, updated_at, updated_by, replaced_at, replaced_by, deleted)
			 SELECT env_id, name_mac, iv, ct, version, updated_at, updated_by, ?3, ?4, 0 FROM secrets WHERE env_id = ?1 AND name_mac = ?2")
		.b(env_id)
		.b(mac)
		.b(now)
		.b(by),
		q("INSERT INTO secrets (env_id, name_mac, iv, ct, version, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
			 ON CONFLICT (env_id, name_mac) DO UPDATE SET
			   iv = excluded.iv, ct = excluded.ct, version = secrets.version + 1,
			   updated_at = excluded.updated_at, updated_by = excluded.updated_by")
		.b(env_id)
		.b(mac)
		.b(&s.iv)
		.b(&s.ct)
		.b(now)
		.b(by),
	])
	.await?;
	get_secret(db, env_id, mac).await?.ok_or_else(|| Error::Internal("secret missing after put".into()))
}

/// Returns false when there was nothing to delete.
pub async fn delete_secret(db: &impl Db, env_id: &str, mac: &str, by: &str, now: i64) -> R<bool> {
	let r = db
		.batch_(vec![
			q("INSERT INTO secret_history (env_id, name_mac, iv, ct, version, updated_at, updated_by, replaced_at, replaced_by, deleted)
				 SELECT env_id, name_mac, iv, ct, version, updated_at, updated_by, ?3, ?4, 1 FROM secrets WHERE env_id = ?1 AND name_mac = ?2")
			.b(env_id)
			.b(mac)
			.b(now)
			.b(by),
			q("DELETE FROM secrets WHERE env_id = ? AND name_mac = ?").b(env_id).b(mac),
		])
		.await?;
	Ok(r.get(1).is_some_and(|x| x.changes == 1))
}

pub async fn secret_history(db: &impl Db, env_id: &str, mac: &str) -> R<Vec<Row>> {
	db.all(
		q("SELECT h.iv, h.ct, h.version, h.updated_at AS updatedAt, h.replaced_at AS replacedAt, h.deleted,
		        COALESCE((SELECT username FROM users WHERE 'user:' || id = h.updated_by), replace(h.updated_by, 'machine:', 'client ')) AS updatedBy,
		        COALESCE((SELECT username FROM users WHERE 'user:' || id = h.replaced_by), replace(h.replaced_by, 'machine:', 'client ')) AS replacedBy
		 FROM secret_history h WHERE h.env_id = ? AND h.name_mac = ? ORDER BY h.id DESC LIMIT 50")
		.b(env_id)
		.b(mac),
	)
	.await
}
