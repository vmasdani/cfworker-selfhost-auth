//! Dashboard API (session cookie): user key pairs, projects, environments, members, secrets and machine
//! identities (port of `worker/projects.ts`). Every key the server stores here is wrapped client-side.

use crate::common::{
	env_membership, env_name, is_client_id, is_mac, is_uuid, member_wrap, membership, param, project_name, role, sealed_key, uuid,
};
use crate::secrets::{delete_secret, get_secret, list_secrets, put_secret, secret_body, secret_history};
use cfsa_core::accounts::{Ctx, json_string, parse_json};
use cfsa_core::db::{Db, DbExt, RowExt, q};
use cfsa_core::http::{Error, R, Resp, bad, bad_msg, err, err_msg};
use cfsa_core::validate::{self as v};
use serde_json::{Map, Value, json};

const MAX_ENVS: usize = 20;
const MAX_PROJECTS_PER_USER: i64 = 200;

fn user_tag<D: Db>(c: &Ctx<'_, D>) -> String {
	format!("user:{}", c.user().id)
}

/// Maps a UNIQUE constraint failure to a 409, like the TS `String(e).includes("UNIQUE")` checks.
fn unique(e: Error, conflict: Error) -> Error {
	match &e {
		Error::Internal(m) if m.contains("UNIQUE") => conflict,
		_ => e,
	}
}

pub async fn route<D: Db>(c: &mut Ctx<'_, D>, m: &str, s: &[&str]) -> R<Option<Resp>> {
	Ok(Some(match (m, s) {
		// --- the user's own ECDH key pair ---
		("GET", ["keys"]) => {
			let row = c.db.first(q("SELECT public_key, wrapped_private_key FROM user_keys WHERE user_id = ?").b(&c.user().id)).await?;
			Resp::ok(match row {
				Some(r) => json!({ "publicKey": r.s("public_key"), "wrappedPrivateKey": parse_json(&r.s("wrapped_private_key")) }),
				None => json!({ "publicKey": null }),
			})
		}
		// Set once. The vault key never changes (password change and recovery re-wrap it), so neither does this.
		("PUT", ["keys"]) => {
			let b = c.body()?;
			let public_key = v::b64(&b, "publicKey", None, 256)?;
			let wrapped = sealed_key(&b, "wrappedPrivateKey")?;
			let n =
				c.db.run(
					q(
						"INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id) DO NOTHING",
					)
					.b(&c.user().id)
					.b(&public_key)
					.b(json_string(&wrapped))
					.b(c.now),
				)
				.await?;
			if n != 1 {
				return Err(err_msg(409, "keys_exist", "This account already has a key pair"));
			}
			c.audit(Some(&c.user().id), "keys_create", None).await?;
			Resp::ok_true()
		}
		("GET", ["users", name, "key"]) => {
			let mut o = Map::new();
			o.insert("username".into(), Value::from(*name));
			let u = v::username(&o, "username")?;
			let row =
				c.db.first(
					q("SELECT u.id, u.username, k.public_key AS publicKey FROM users u LEFT JOIN user_keys k ON k.user_id = u.id
					 WHERE u.username = ? AND u.disabled = 0")
					.b(&u),
				)
				.await?
				.ok_or_else(|| err_msg(404, "user_not_found", "No such user"))?;
			let Some(pk) = row.os("publicKey") else {
				return Err(err_msg(409, "user_has_no_keys", "That user has not signed in to Coffer yet"));
			};
			Resp::ok(json!({ "userId": row.s("id"), "username": row.s("username"), "publicKey": pk }))
		}

		// --- projects ---
		("GET", ["projects"]) => projects_list(c).await?,
		("POST", ["projects"]) => project_create(c).await?,
		("PATCH", ["projects", pid]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, true).await?;
			let name = project_name(&c.body()?)?;
			c.db.run(q("UPDATE projects SET name = ? WHERE id = ?").b(&name).b(pid)).await?;
			Resp::ok_true()
		}
		("DELETE", ["projects", pid]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, true).await?;
			c.db.run(q("DELETE FROM projects WHERE id = ?").b(pid)).await?;
			c.audit(Some(&c.user().id), "project_delete", Some(json!({ "projectId": pid }))).await?;
			Resp::ok_true()
		}

		// --- environments ---
		("POST", ["projects", pid, "environments"]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, true).await?;
			let b = c.body()?;
			let id = uuid(&b, "id")?;
			let name = env_name(&b)?;
			let wrapped = sealed_key(&b, "wrappedKey")?;
			let n =
				c.db.first(q("SELECT COUNT(*) AS n, COALESCE(MAX(position), -1) AS max FROM environments WHERE project_id = ?").b(pid))
					.await?;
			let (count, max) = n.map_or((0, -1), |r| (r.i("n"), r.oi("max").unwrap_or(-1)));
			if count >= MAX_ENVS as i64 {
				return Err(bad("too_many_environments"));
			}
			c.db.run(
				q("INSERT INTO environments (id, project_id, name, position, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?)")
					.b(&id)
					.b(pid)
					.b(&name)
					.b(max + 1)
					.b(json_string(&wrapped))
					.b(c.now),
			)
			.await
			.map_err(|e| unique(e, err_msg(409, "environment_exists", "An environment with that name exists")))?;
			c.audit(Some(&c.user().id), "environment_create", Some(json!({ "projectId": pid, "envId": id }))).await?;
			Resp::ok_true()
		}
		("PATCH", ["environments", eid]) => {
			let eid = param(eid, is_uuid)?;
			let mm = env_membership(c, eid).await?;
			if mm.role != "owner" {
				return Err(err(403, "owner_only"));
			}
			let name = env_name(&c.body()?)?;
			c.db.run(q("UPDATE environments SET name = ? WHERE id = ?").b(&name).b(eid))
				.await
				.map_err(|e| unique(e, err_msg(409, "environment_exists", "An environment with that name exists")))?;
			Resp::ok_true()
		}
		("DELETE", ["environments", eid]) => {
			let eid = param(eid, is_uuid)?;
			let mm = env_membership(c, eid).await?;
			if mm.role != "owner" {
				return Err(err(403, "owner_only"));
			}
			let n =
				c.db.first(q("SELECT COUNT(*) AS n FROM environments WHERE project_id = ?").b(&mm.project_id))
					.await?
					.map_or(0, |r| r.i("n"));
			if n <= 1 {
				return Err(bad_msg("last_environment", "A project needs at least one environment"));
			}
			c.db.run(q("DELETE FROM environments WHERE id = ?").b(eid)).await?;
			c.audit(Some(&c.user().id), "environment_delete", Some(json!({ "projectId": mm.project_id, "envId": eid }))).await?;
			Resp::ok_true()
		}

		// --- members ---
		("GET", ["projects", pid, "members"]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, false).await?;
			let rows =
				c.db.all(
					q("SELECT u.id AS userId, u.username, m.role, m.created_at AS addedAt FROM project_members m
					 JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY m.created_at")
					.b(pid),
				)
				.await?;
			Resp::ok(json!({ "members": rows }))
		}
		// The owner fetched the user's public key and wrapped the project key to it.
		("POST", ["projects", pid, "members"]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, true).await?;
			let b = c.body()?;
			let user_id = uuid(&b, "userId")?;
			let r = role(&b)?;
			let wrapped = member_wrap(&b, "wrappedKey")?;
			let target = c
				.db
				.first(q("SELECT u.id FROM users u JOIN user_keys k ON k.user_id = u.id WHERE u.id = ? AND u.disabled = 0").b(&user_id))
				.await?;
			if target.is_none() {
				return Err(err(404, "user_not_found"));
			}
			let n = c
				.db
				.run(
					q("INSERT INTO project_members (project_id, user_id, role, wrapped_key, added_by, created_at) VALUES (?, ?, ?, ?, ?, ?)
					 ON CONFLICT (project_id, user_id) DO NOTHING")
					.b(pid)
					.b(&user_id)
					.b(&r)
					.b(wrapped.to_string())
					.b(&c.user().id)
					.b(c.now),
				)
				.await?;
			if n != 1 {
				return Err(err_msg(409, "already_member", "That user is already a member"));
			}
			c.audit(Some(&c.user().id), "member_add", Some(json!({ "projectId": pid, "userId": user_id, "role": r }))).await?;
			Resp::ok_true()
		}
		("PATCH", ["projects", pid, "members", uid]) => {
			let pid = param(pid, is_uuid)?;
			let uid = param(uid, is_uuid)?;
			membership(c, pid, true).await?;
			let r = role(&c.body()?)?;
			if r == "member" {
				assert_another_owner(c, pid, uid).await?;
			}
			c.db.run(q("UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?").b(&r).b(pid).b(uid)).await?;
			Resp::ok_true()
		}
		// Owners can remove anyone; members can remove themselves. Removal does not rotate keys: a removed
		// member who kept a copy of the project key could still decrypt ciphertext obtained some other way.
		("DELETE", ["projects", pid, "members", uid]) => {
			let pid = param(pid, is_uuid)?;
			let uid = param(uid, is_uuid)?;
			let me = c.user().id.clone();
			membership(c, pid, uid != me).await?;
			assert_another_owner(c, pid, uid).await?;
			c.db.run(q("DELETE FROM project_members WHERE project_id = ? AND user_id = ?").b(pid).b(uid)).await?;
			c.audit(Some(&me), "member_remove", Some(json!({ "projectId": pid, "userId": uid }))).await?;
			Resp::ok_true()
		}

		// --- secrets ---
		("GET", ["environments", eid, "secrets"]) => {
			let eid = param(eid, is_uuid)?;
			env_membership(c, eid).await?;
			Resp::ok(json!({ "secrets": list_secrets(c.db, eid).await? }))
		}
		("PUT", ["environments", eid, "secrets", mac]) => {
			let eid = param(eid, is_uuid)?;
			let mac = param(mac, is_mac)?;
			env_membership(c, eid).await?;
			let body = secret_body(&c.body()?)?;
			Resp::ok(Value::Object(put_secret(c.db, eid, mac, &body, &user_tag(c), c.now).await?))
		}
		("DELETE", ["environments", eid, "secrets", mac]) => {
			let eid = param(eid, is_uuid)?;
			let mac = param(mac, is_mac)?;
			env_membership(c, eid).await?;
			Resp::ok(json!({ "deleted": delete_secret(c.db, eid, mac, &user_tag(c), c.now).await? }))
		}
		("GET", ["environments", eid, "secrets", mac]) => {
			let eid = param(eid, is_uuid)?;
			let mac = param(mac, is_mac)?;
			env_membership(c, eid).await?;
			match get_secret(c.db, eid, mac).await? {
				Some(r) => Resp::ok(Value::Object(r)),
				None => return Err(err(404, "secret_not_found")),
			}
		}
		("GET", ["environments", eid, "secrets", mac, "history"]) => {
			let eid = param(eid, is_uuid)?;
			let mac = param(mac, is_mac)?;
			env_membership(c, eid).await?;
			Resp::ok(json!({ "history": secret_history(c.db, eid, mac).await? }))
		}

		// --- machine identities ---
		("GET", ["projects", pid, "identities"]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, false).await?;
			let rows =
				c.db.all(
					q("SELECT i.id, i.env_id AS envId, i.name, i.scope, i.created_at AS createdAt, i.last_used_at AS lastUsedAt,
					        u.username AS createdBy
					 FROM machine_identities i LEFT JOIN users u ON u.id = i.created_by
					 WHERE i.project_id = ? AND i.revoked_at IS NULL ORDER BY i.created_at DESC")
					.b(pid),
				)
				.await?;
			Resp::ok(json!({ "identities": rows }))
		}
		// The browser generated the client secret; the server receives only the derived auth key (stored as
		// an HMAC) and the environment key wrapped by the secret's wrap key.
		("POST", ["projects", pid, "identities"]) => {
			let pid = param(pid, is_uuid)?;
			membership(c, pid, true).await?;
			let b = c.body()?;
			let id = v::str_max(&b, "id", 26)?;
			if !is_client_id(&id) {
				return Err(bad_msg("invalid_request", "Invalid client ID"));
			}
			let env_id = uuid(&b, "envId")?;
			let name = project_name(&b)?;
			let scope = v::str_max(&b, "scope", 5)?;
			if scope != "read" && scope != "write" {
				return Err(bad("invalid_scope"));
			}
			let auth_key = v::b64_bytes(&b, "authKey", 32)?;
			let wrapped = sealed_key(&b, "wrappedKey")?;
			let env = c.db.first(q("SELECT 1 FROM environments WHERE id = ? AND project_id = ?").b(&env_id).b(pid)).await?;
			if env.is_none() {
				return Err(err(404, "environment_not_found"));
			}
			c.db.run(
				q("INSERT INTO machine_identities (id, project_id, env_id, name, scope, auth_verifier, wrapped_key, created_by, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
				.b(&id)
				.b(pid)
				.b(&env_id)
				.b(&name)
				.b(&scope)
				.b(c.keys.verifier(&auth_key))
				.b(json_string(&wrapped))
				.b(&c.user().id)
				.b(c.now),
			)
			.await
			.map_err(|e| unique(e, err(409, "id_conflict")))?;
			c.audit(
				Some(&c.user().id),
				"identity_create",
				Some(json!({ "projectId": pid, "envId": env_id, "clientId": id, "scope": scope })),
			)
			.await?;
			Resp::ok_true()
		}
		("DELETE", ["identities", id]) => {
			let id = param(id, is_client_id)?;
			let row =
				c.db.first(q("SELECT project_id AS projectId FROM machine_identities WHERE id = ? AND revoked_at IS NULL").b(id))
					.await?
					.ok_or_else(|| err(404, "not_found"))?;
			let pid = row.s("projectId");
			membership(c, &pid, true).await?;
			c.db.run(q("UPDATE machine_identities SET revoked_at = ? WHERE id = ?").b(c.now).b(id)).await?;
			c.audit(Some(&c.user().id), "identity_revoke", Some(json!({ "projectId": pid, "clientId": id }))).await?;
			Resp::ok_true()
		}
		_ => return Ok(None),
	}))
}

/// Everything the dashboard needs after unlock, in one request.
async fn projects_list<D: Db>(c: &Ctx<'_, D>) -> R<Resp> {
	let uid = &c.user().id;
	let res =
		c.db.batch_(vec![
			q("SELECT p.id, p.name, p.created_at AS createdAt, m.role, m.wrapped_key AS wrappedKey
				 FROM projects p JOIN project_members m ON m.project_id = p.id AND m.user_id = ? ORDER BY p.name COLLATE NOCASE")
			.b(uid),
			q("SELECT e.id, e.project_id AS projectId, e.name, e.position, e.wrapped_key AS wrappedKey,
				        (SELECT COUNT(*) FROM secrets s WHERE s.env_id = e.id) AS secretCount
				 FROM environments e JOIN project_members m ON m.project_id = e.project_id AND m.user_id = ?
				 ORDER BY e.position, e.created_at")
			.b(uid),
		])
		.await?;
	let mut by_project: Map<String, Value> = Map::new();
	for e in res.get(1).map(|r| r.rows.as_slice()).unwrap_or_default() {
		let entry = json!({
			"id": e.s("id"),
			"name": e.s("name"),
			"position": e.i("position"),
			"secretCount": e.i("secretCount"),
			"wrappedKey": parse_json(&e.s("wrappedKey")),
		});
		if let Value::Array(list) = by_project.entry(e.s("projectId")).or_insert_with(|| Value::Array(Vec::new())) {
			list.push(entry);
		}
	}
	let projects: Vec<Value> = res
		.first()
		.map(|r| r.rows.clone())
		.unwrap_or_default()
		.into_iter()
		.map(|mut p| {
			let wk = parse_json(&p.s("wrappedKey"));
			p.insert("wrappedKey".into(), wk);
			let envs = by_project.get(&p.s("id")).cloned().unwrap_or_else(|| Value::Array(Vec::new()));
			p.insert("environments".into(), envs);
			Value::Object(p)
		})
		.collect();
	Ok(Resp::ok(json!({ "projects": projects })))
}

// IDs are client-generated: they are bound into the ciphertext (AAD) before the server sees them.
async fn project_create<D: Db>(c: &Ctx<'_, D>) -> R<Resp> {
	let b = c.body()?;
	let id = uuid(&b, "id")?;
	let name = project_name(&b)?;
	let wrapped = member_wrap(&b, "wrappedKey")?;
	let list = match b.get("environments") {
		Some(Value::Array(a)) if (1..=MAX_ENVS).contains(&a.len()) => a,
		_ => return Err(bad_msg("invalid_request", &format!("environments: 1–{MAX_ENVS} items"))),
	};
	let mut envs = Vec::new();
	for e in list {
		let o = v::obj(e, "environment")?;
		envs.push((uuid(o, "id")?, env_name(o)?, sealed_key(o, "wrappedKey")?));
	}
	let mut names: Vec<String> = envs.iter().map(|(_, n, _)| n.to_lowercase()).collect();
	names.sort();
	names.dedup();
	if names.len() != envs.len() {
		return Err(bad("duplicate_environment"));
	}
	let uid = c.user().id.clone();
	let count = c.db.first(q("SELECT COUNT(*) AS n FROM project_members WHERE user_id = ?").b(&uid)).await?.map_or(0, |r| r.i("n"));
	if count >= MAX_PROJECTS_PER_USER {
		return Err(bad("too_many_projects"));
	}
	let mut stmts = vec![
		q("INSERT INTO projects (id, name, created_by, created_at) VALUES (?, ?, ?, ?)").b(&id).b(&name).b(&uid).b(c.now),
		q("INSERT INTO project_members (project_id, user_id, role, wrapped_key, added_by, created_at) VALUES (?, ?, 'owner', ?, ?, ?)")
			.b(&id)
			.b(&uid)
			.b(wrapped.to_string())
			.b(&uid)
			.b(c.now),
	];
	for (i, (eid, ename, wk)) in envs.iter().enumerate() {
		stmts.push(
			q("INSERT INTO environments (id, project_id, name, position, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?)")
				.b(eid)
				.b(&id)
				.b(ename)
				.b(i as i64)
				.b(json_string(wk))
				.b(c.now),
		);
	}
	c.db.batch_(stmts).await.map_err(|e| unique(e, err(409, "id_conflict")))?;
	c.audit(Some(&uid), "project_create", Some(json!({ "projectId": id }))).await?;
	Ok(Resp::ok_true())
}

async fn assert_another_owner<D: Db>(c: &Ctx<'_, D>, project_id: &str, leaving: &str) -> R<()> {
	let n =
		c.db.first(
			q("SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND role = 'owner' AND user_id != ?")
				.b(project_id)
				.b(leaving),
		)
		.await?
		.map_or(0, |r| r.i("n"));
	if n < 1 {
		return Err(bad_msg("last_owner", "A project needs at least one owner"));
	}
	Ok(())
}
