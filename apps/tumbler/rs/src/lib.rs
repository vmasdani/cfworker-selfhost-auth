//! Tumbler API in Rust: a port of `apps/tumbler/worker` (accounts + encrypted entry sync).
//!
//! The cookie name and AAD prefix must not change: existing sessions and login TOTP secrets use them.

use cfsa_core::accounts::{AccountsConfig, App, Ctx};
use cfsa_core::db::{Db, DbExt, RowExt, q};
use cfsa_core::http::{R, Resp, bad_msg};
use cfsa_core::validate::{self as v, Obj};
use serde_json::{Value, json};

pub struct Tumbler;

pub static CONFIG: AccountsConfig = AccountsConfig { app_name: "Tumbler", cookie: "__Host-tumbler_session", aad_prefix: "tumbler" };

/// Embedded `apps/tumbler/migrations`, applied by the standalone server (on D1 the installer applies them).
pub static MIGRATIONS: &[(&str, &str)] = &[
	("0001_init.sql", include_str!("../../migrations/0001_init.sql")),
	("0002_sync_ratelimit.sql", include_str!("../../migrations/0002_sync_ratelimit.sql")),
];

impl App for Tumbler {
	fn config(&self) -> &AccountsConfig {
		&CONFIG
	}

	async fn route<D: Db>(&self, c: &mut Ctx<'_, D>, m: &str, segs: &[String]) -> R<Option<Resp>> {
		let s: Vec<&str> = segs.iter().map(String::as_str).collect();
		Ok(Some(match (m, s.as_slice()) {
			("GET", ["sync"]) => sync_pull(c).await?,
			("POST", ["sync"]) => sync_push(c).await?,
			_ => return Ok(None),
		}))
	}
}

// Encrypted entry sync. The server only ever sees ciphertext.
//
// Push: each change is accepted if it is newer than the stored one (client updatedAt, then revision):
// last-write-wins per entry, decided atomically in SQL. Accepted rows get the next per-user `seq`.
// Pull: rows with seq > cursor, oldest first.

const MAX_CHANGES: usize = 500;
const PAGE: i64 = 500;
const MAX_CT: usize = 16_384;
const MAX_CLOCK_SKEW_MS: i64 = 24 * 60 * 60 * 1000;

struct Change {
	id: String,
	iv: String,
	ct: String,
	revision: i64,
	updated_at: i64,
	deleted: bool,
}

fn parse_change(val: &Value, now: i64) -> R<Change> {
	let o: &Obj = v::obj(val, "change")?;
	let id = v::str_max(o, "id", 64)?;
	if !v::chars_in(&id, 1, 64, |c| c.is_ascii_alphanumeric() || c == b'-') {
		return Err(bad_msg("invalid_request", "Invalid entry id"));
	}
	let deleted = v::boolean(o, "deleted")?;
	Ok(Change {
		iv: if deleted { String::new() } else { v::b64(o, "iv", Some(12), 65536)? },
		ct: if deleted { String::new() } else { v::b64(o, "ct", None, MAX_CT)? },
		revision: v::int(o, "revision", 1, 9_007_199_254_740_991)?,
		// A client with a clock far in the future would otherwise win every conflict forever.
		updated_at: v::int(o, "updatedAt", 0, now + MAX_CLOCK_SKEW_MS)?,
		id,
		deleted,
	})
}

/// `Number(s)` for a query parameter, accepted only as a non-negative safe integer.
fn cursor(raw: Option<String>) -> Option<i64> {
	let s = raw.unwrap_or_else(|| "0".into());
	let t = cfsa_core::text::js_trim(&s);
	if t.is_empty() {
		return Some(0);
	}
	let f: f64 = t.parse().ok().filter(|_| !t.contains(['i', 'I', 'n', 'N']))?;
	(f.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&f)).then_some(f as i64)
}

async fn sync_pull<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let since = cursor(c.req.query_param("since")).ok_or_else(|| bad_msg("invalid_request", "Invalid cursor"))?;
	let rows =
		c.db.all(
			q("SELECT id, iv, ciphertext AS ct, revision, updated_at AS updatedAt, deleted, seq
			 FROM entries WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?")
			.b(&c.user().id)
			.b(since)
			.b(PAGE),
		)
		.await?;
	let next = rows.last().map_or(since, |r| r.i("seq"));
	let more = rows.len() as i64 == PAGE;
	let entries: Vec<Value> = rows
		.into_iter()
		.map(|mut r| {
			let d = r.i("deleted") == 1;
			r.insert("deleted".into(), Value::Bool(d));
			Value::Object(r)
		})
		.collect();
	Ok(Resp::ok(json!({ "entries": entries, "cursor": next, "more": more })))
}

async fn sync_push<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let b = c.body()?;
	let list = match b.get("changes") {
		Some(Value::Array(a)) if a.len() <= MAX_CHANGES => a,
		_ => return Err(bad_msg("invalid_request", &format!("changes: array of at most {MAX_CHANGES}"))),
	};
	let changes = list.iter().map(|x| parse_change(x, c.now)).collect::<R<Vec<_>>>()?;
	if changes.is_empty() {
		return Ok(Resp::ok(json!({ "results": [] })));
	}
	let uid = c.user().id.clone();
	let stmts = changes
		.iter()
		.map(|ch| {
			q("INSERT INTO entries (user_id, id, ciphertext, iv, revision, updated_at, deleted, seq)
				 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, (SELECT COALESCE(MAX(seq), 0) + 1 FROM entries WHERE user_id = ?1))
				 ON CONFLICT (user_id, id) DO UPDATE SET
				   ciphertext = excluded.ciphertext, iv = excluded.iv, revision = excluded.revision,
				   updated_at = excluded.updated_at, deleted = excluded.deleted, seq = excluded.seq
				 WHERE excluded.updated_at > entries.updated_at
				    OR (excluded.updated_at = entries.updated_at AND excluded.revision > entries.revision)")
			.b(&uid)
			.b(&ch.id)
			.b(&ch.ct)
			.b(&ch.iv)
			.b(ch.revision)
			.b(ch.updated_at)
			.b(if ch.deleted { 1 } else { 0 })
		})
		.collect();
	let res = c.db.batch_(stmts).await?;
	let results: Vec<Value> = changes.iter().zip(&res).map(|(ch, r)| json!({ "id": ch.id, "accepted": r.changes == 1 })).collect();
	Ok(Resp::ok(json!({ "results": results })))
}

#[cfg(target_arch = "wasm32")]
#[worker::event(fetch)]
async fn fetch(req: worker::Request, env: worker::Env, _ctx: worker::Context) -> worker::Result<worker::Response> {
	cfsa_core::worker_glue::fetch(&Tumbler, req, env).await
}

#[cfg(test)]
mod tests {
	use super::cursor;

	#[test]
	fn migrations_are_all_embedded() {
		let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../migrations");
		let mut on_disk: Vec<String> = std::fs::read_dir(dir)
			.unwrap()
			.filter_map(|e| e.ok()?.file_name().into_string().ok())
			.filter(|n| n.ends_with(".sql"))
			.collect();
		on_disk.sort();
		let embedded: Vec<&str> = super::MIGRATIONS.iter().map(|(n, _)| *n).collect();
		assert_eq!(on_disk, embedded, "add new migrations to MIGRATIONS");
	}

	#[test]
	fn cursor_matches_number() {
		assert_eq!(cursor(None), Some(0));
		assert_eq!(cursor(Some("".into())), Some(0));
		assert_eq!(cursor(Some(" 12 ".into())), Some(12));
		assert_eq!(cursor(Some("1e3".into())), Some(1000));
		assert_eq!(cursor(Some("-1".into())), None);
		assert_eq!(cursor(Some("1.5".into())), None);
		assert_eq!(cursor(Some("inf".into())), None);
		assert_eq!(cursor(Some("abc".into())), None);
	}
}
