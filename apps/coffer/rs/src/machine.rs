//! Machine REST API (`/api/v1`), used by the SDK snippets (port of `worker/machine.ts`).
//!
//!   Authorization: Bearer <client id>.<base64 auth key>
//!
//! The auth key is HKDF(client secret, "coffer/v1/machine-auth"); the server stores HMAC(SERVER_SECRET,
//! auth key). The client secret itself never leaves the client, and neither does the wrap key derived
//! from it, which unwraps the environment key returned by GET /v1/identity.

use crate::common::{is_client_id, is_mac, param};
use crate::secrets::{delete_secret, get_secret, list_secrets, put_secret, secret_body};
use cfsa_core::accounts::{Ctx, parse_json};
use cfsa_core::db::{Db, DbExt, Row, RowExt, q};
use cfsa_core::http::{R, Resp, err, err_msg};
use cfsa_core::rate_limit::{Limit, assert_not_limited, hit, limit};
use serde_json::{Value, json};

const MIN: i64 = 60_000;
const TOUCH_EVERY_MS: i64 = 60 * MIN;

/// `^Bearer (cfi_[A-Za-z0-9_-]{22})\.([A-Za-z0-9+/]{43}=)$` -> (client id, auth key)
fn parse_auth(h: &str) -> Option<(&str, &str)> {
	let rest = h.strip_prefix("Bearer ")?;
	let (id, key) = rest.split_once('.')?;
	let key_ok =
		key.len() == 44 && key.ends_with('=') && key.as_bytes()[..43].iter().all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/');
	(is_client_id(id) && key_ok).then_some((id, key))
}

fn limits<D: Db>(c: &Ctx<'_, D>, client_id: &str) -> Vec<Limit> {
	vec![limit(format!("machine:id:{client_id}"), 30, 15 * MIN), limit(format!("machine:ip:{}", c.client_ip()), 60, 15 * MIN)]
}

async fn machine<D: Db>(c: &Ctx<'_, D>) -> R<Row> {
	let Some((client_id, auth_key)) = parse_auth(c.req.header("authorization").unwrap_or("")) else {
		return Err(err_msg(401, "unauthenticated", "Send Authorization: Bearer <client id>.<auth key>"));
	};
	let l = limits(c, client_id);
	assert_not_limited(c.db, &l, c.now).await?;
	let row =
		c.db.first(
			q("SELECT i.id, i.project_id, i.env_id, i.scope, i.auth_verifier, i.wrapped_key, i.last_used_at,
			        p.name AS project, e.name AS environment
			 FROM machine_identities i JOIN projects p ON p.id = i.project_id JOIN environments e ON e.id = i.env_id
			 WHERE i.id = ? AND i.revoked_at IS NULL")
			.b(client_id),
		)
		.await?;
	let row = match row {
		Some(r) if c.keys.verify(auth_key, &r.s("auth_verifier")) => r,
		_ => {
			hit(c.db, &l, c.now).await?;
			return Err(err_msg(401, "invalid_credentials", "Unknown or revoked client ID, or wrong client secret"));
		}
	};
	// The TS Worker defers this with waitUntil; it is one small write per client per hour.
	let last = row.oi("last_used_at").unwrap_or(0);
	if last == 0 || c.now - last > TOUCH_EVERY_MS {
		c.db.run(q("UPDATE machine_identities SET last_used_at = ? WHERE id = ?").b(c.now).b(row.s("id"))).await?;
	}
	Ok(row)
}

fn require_write(id: &Row) -> R<()> {
	if id.s("scope") != "write" {
		return Err(err_msg(403, "read_only", "This client ID has read-only access"));
	}
	Ok(())
}

pub async fn route<D: Db>(c: &mut Ctx<'_, D>, m: &str, s: &[&str]) -> R<Option<Resp>> {
	Ok(Some(match (m, s) {
		("GET", ["identity"]) => {
			let id = machine(c).await?;
			Resp::ok(json!({
				"clientId": id.s("id"),
				"scope": id.s("scope"),
				"projectId": id.s("project_id"),
				"project": id.s("project"),
				"envId": id.s("env_id"),
				"environment": id.s("environment"),
				"wrappedKey": parse_json(&id.s("wrapped_key")),
			}))
		}
		("GET", ["secrets"]) => {
			let id = machine(c).await?;
			Resp::ok(json!({ "secrets": list_secrets(c.db, &id.s("env_id")).await? }))
		}
		("GET", ["secrets", mac]) => {
			let id = machine(c).await?;
			let mac = param(mac, is_mac)?;
			match get_secret(c.db, &id.s("env_id"), mac).await? {
				Some(r) => Resp::ok(Value::Object(r)),
				None => return Err(err(404, "secret_not_found")),
			}
		}
		("PUT", ["secrets", mac]) => {
			let id = machine(c).await?;
			require_write(&id)?;
			let mac = param(mac, is_mac)?;
			let body = secret_body(&c.body()?)?;
			let row = put_secret(c.db, &id.s("env_id"), mac, &body, &format!("machine:{}", id.s("id")), c.now).await?;
			Resp::ok(Value::Object(row))
		}
		("DELETE", ["secrets", mac]) => {
			let id = machine(c).await?;
			require_write(&id)?;
			let mac = param(mac, is_mac)?;
			Resp::ok(json!({ "deleted": delete_secret(c.db, &id.s("env_id"), mac, &format!("machine:{}", id.s("id")), c.now).await? }))
		}
		_ => return Ok(None),
	}))
}

#[cfg(test)]
mod tests {
	use super::parse_auth;

	#[test]
	fn bearer() {
		let key = format!("{}=", "A".repeat(43));
		let h = format!("Bearer cfi_{}.{key}", "x".repeat(22));
		assert_eq!(parse_auth(&h).map(|(_, k)| k.len()), Some(44));
		assert!(parse_auth("Bearer nope").is_none());
		assert!(parse_auth(&format!("bearer cfi_{}.{key}", "x".repeat(22))).is_none());
		assert!(parse_auth(&format!("Bearer cfi_{}.{}", "x".repeat(22), "A".repeat(44))).is_none());
	}
}
