//! Port of `packages/server-kit/src/rate-limit.ts`: fixed-window failure counters in `rate_limits`.

use crate::db::{Db, DbExt, RowExt, q};
use crate::http::{Error, HttpError, R};
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
pub struct Limit {
	pub key: String,
	pub max: i64,
	pub window_ms: i64,
}

pub fn limit(key: String, max: i64, window_ms: i64) -> Limit {
	Limit { key, max, window_ms }
}

/// 429 if any of the limits is exhausted.
pub async fn assert_not_limited(db: &impl Db, limits: &[Limit], now: i64) -> R<()> {
	for l in limits {
		let row = db.first(q("SELECT count, window_start FROM rate_limits WHERE key = ?").b(&l.key)).await?;
		if let Some(r) = row {
			let (count, start) = (r.i("count"), r.i("window_start"));
			if now - start < l.window_ms && count >= l.max {
				// Math.ceil of a positive millisecond remainder.
				let retry_after = (start + l.window_ms - now + 999).div_euclid(1000);
				let mut extra = Map::new();
				extra.insert("retryAfter".into(), Value::from(retry_after));
				return Err(Error::Http(Box::new(HttpError {
					status: 429,
					code: "rate_limited".into(),
					message: "Too many attempts. Try again later.".into(),
					extra,
				})));
			}
		}
	}
	Ok(())
}

/// Count one failure (or one use, for endpoints limited regardless of outcome).
pub async fn hit(db: &impl Db, limits: &[Limit], now: i64) -> R<()> {
	let stmts = limits
		.iter()
		.map(|l| {
			q("INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)
				 ON CONFLICT(key) DO UPDATE SET
				   count = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE count + 1 END,
				   window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END")
			.b(&l.key)
			.b(now)
			.b(l.window_ms)
		})
		.collect();
	db.batch_(stmts).await?;
	Ok(())
}

pub async fn clear(db: &impl Db, keys: &[String]) -> R<()> {
	if !keys.is_empty() {
		db.batch_(keys.iter().map(|k| q("DELETE FROM rate_limits WHERE key = ?").b(k)).collect()).await?;
	}
	Ok(())
}
