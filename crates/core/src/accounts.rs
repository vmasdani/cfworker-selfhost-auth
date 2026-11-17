//! Port of `packages/worker-accounts`: the `/api` app shell (CSRF and JSON checks, errors, no-store),
//! sessions, pre-login, login (+ TOTP), first-admin setup, invite registration, recovery, password,
//! login TOTP and admin invites. Same routes, SQL, status codes and JSON as the Hono version.

use crate::crypto::{Sealed, random_bytes, random_uuid, sha256, to_b64, to_b64url};
use crate::db::{Db, DbExt, Row, RowExt, Stmt, q};
use crate::http::{R, Req, Resp, bad, err, err_msg};
use crate::keys::ServerKeys;
use crate::rate_limit::{Limit, assert_not_limited, clear, hit, limit};
use crate::session::{self, SessionRow};
use crate::text::{js_trim, percent_decode};
use crate::totp::{base32_decode, base32_encode, hotp_sha1, otpauth_totp_uri, totp_counter};
use crate::validate::{self as v, AccountMaterial, DEFAULT_PBKDF2_ITERATIONS, Obj};
use serde_json::{Value, json};

pub struct AccountsConfig {
	/// Shown in the login TOTP issuer, e.g. "Tumbler (host)".
	pub app_name: &'static str,
	/// Session cookie name; must start with `__Host-`. Never change it once deployed.
	pub cookie: &'static str,
	/// AAD namespace for the server-sealed login TOTP secret. Never change it once deployed.
	pub aad_prefix: &'static str,
}

/// The bindings every app with accounts has.
pub struct Env<D: Db> {
	pub db: D,
	/// Err when SERVER_SECRET is missing or too short: every request then fails with 500.
	pub keys: Result<ServerKeys, String>,
	pub admin_setup_token: String,
}

impl<D: Db> Env<D> {
	pub fn new(db: D, server_secret: &str, admin_setup_token: String) -> Env<D> {
		Env { db, keys: ServerKeys::new(server_secret), admin_setup_token }
	}
}

#[derive(Clone, Debug)]
pub struct UserRow {
	pub id: String,
	pub username: String,
	pub role: String,
	pub auth_verifier: String,
	pub kdf_params: String,
	pub wrapped_vault_key: String,
	pub recovery_wrapped_key: String,
	pub recovery_verifier: String,
	pub login_totp_secret_enc: Option<String>,
	pub login_totp_enabled: i64,
	pub login_totp_last_counter: i64,
	pub disabled: i64,
	pub created_at: i64,
}

const USER_COLUMNS: &str = "id, username, role, auth_verifier, kdf_params, wrapped_vault_key, recovery_wrapped_key, recovery_verifier, \
	login_totp_secret_enc, login_totp_enabled, login_totp_last_counter, disabled, created_at";

fn user_from(r: &Row) -> UserRow {
	UserRow {
		id: r.s("id"),
		username: r.s("username"),
		role: r.s("role"),
		auth_verifier: r.s("auth_verifier"),
		kdf_params: r.s("kdf_params"),
		wrapped_vault_key: r.s("wrapped_vault_key"),
		recovery_wrapped_key: r.s("recovery_wrapped_key"),
		recovery_verifier: r.s("recovery_verifier"),
		login_totp_secret_enc: r.os("login_totp_secret_enc"),
		login_totp_enabled: r.i("login_totp_enabled"),
		login_totp_last_counter: r.i("login_totp_last_counter"),
		disabled: r.i("disabled"),
		created_at: r.i("created_at"),
	}
}

pub async fn user_by_name(db: &impl Db, username: &str) -> R<Option<UserRow>> {
	Ok(db.first(q(&format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?")).b(username)).await?.as_ref().map(user_from))
}

pub async fn user_by_id(db: &impl Db, id: &str) -> R<Option<UserRow>> {
	Ok(db.first(q(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?")).b(id)).await?.as_ref().map(user_from))
}

/// `JSON.parse` of a stored JSON column (null when unparsable).
pub fn parse_json(s: &str) -> Value {
	serde_json::from_str(s).unwrap_or(Value::Null)
}

/// What a signed-in client receives: enough to unwrap the vault key locally.
pub fn account_response(u: &UserRow) -> Value {
	json!({
		"user": { "id": u.id, "username": u.username, "role": u.role },
		"kdf": parse_json(&u.kdf_params),
		"wrappedVaultKey": parse_json(&u.wrapped_vault_key),
		"totpEnabled": u.login_totp_enabled == 1,
	})
}

/// Per-request context (Hono's `c`).
pub struct Ctx<'a, D: Db> {
	pub env: &'a Env<D>,
	pub db: &'a D,
	pub req: &'a Req,
	pub cfg: &'a AccountsConfig,
	pub keys: &'a ServerKeys,
	pub now: i64,
	user: Option<UserRow>,
	session: Option<SessionRow>,
}

impl<'a, D: Db> Ctx<'a, D> {
	/// The signed-in user; only call after [`Ctx::require_session`].
	pub fn user(&self) -> &UserRow {
		self.user.as_ref().expect("require_session first")
	}

	pub fn session(&self) -> &SessionRow {
		self.session.as_ref().expect("require_session first")
	}

	pub fn body(&self) -> R<Obj> {
		v::body(&self.req.body)
	}

	pub fn client_ip(&self) -> &str {
		&self.req.client_ip
	}

	/// Middleware: require a valid session; sets `user` and `session`.
	pub async fn require_session(&mut self) -> R<()> {
		let token = session::read_session_cookie(self.req.header("cookie"), self.cfg.cookie);
		let s = match token {
			Some(t) => session::find_session(self.db, &t, self.now).await?,
			None => None,
		};
		let Some(s) = s else { return Err(err(401, "unauthenticated")) };
		match user_by_id(self.db, &s.user_id).await? {
			Some(u) if u.disabled == 0 => {
				self.user = Some(u);
				self.session = Some(s);
				Ok(())
			}
			_ => Err(err(401, "unauthenticated")),
		}
	}

	pub fn require_admin(&self) -> R<()> {
		if self.user().role != "admin" {
			return Err(err(403, "admin_only"));
		}
		Ok(())
	}

	pub async fn audit(&self, user_id: Option<&str>, event: &str, meta: Option<Value>) -> R<()> {
		self.db
			.run(
				q("INSERT INTO audit_log (user_id, event, at, meta) VALUES (?, ?, ?, ?)")
					.b(user_id)
					.b(event)
					.b(self.now)
					.b(meta.map(|m| m.to_string())),
			)
			.await?;
		Ok(())
	}
}

/// An app's own routes. `segs` are the decoded path segments after `/api`.
#[allow(async_fn_in_trait)]
pub trait App {
	fn config(&self) -> &AccountsConfig;
	/// Ok(None) when no route matches (the caller answers 404 `not_found`).
	async fn route<D: Db>(&self, c: &mut Ctx<'_, D>, method: &str, segs: &[String]) -> R<Option<Resp>>;
}

/// Serves one `/api` request: the Hono app built by `createApp` plus the shared routes.
pub async fn serve<D: Db, A: App>(app: &A, env: &Env<D>, req: &Req, now: i64) -> Resp {
	let cfg = app.config();
	assert!(cfg.cookie.starts_with("__Host-"), "Session cookie name must start with __Host-");
	let head = req.method == "HEAD";
	let method = if head { "GET" } else { req.method.as_str() };

	if req.path != "/api" && !req.path.starts_with("/api/") {
		return Resp::text(404, "404 Not Found");
	}
	// CSRF: state-changing requests must be same-origin JSON. Browsers send Origin on cross-site
	// requests, and a cross-site form cannot send application/json without a CORS preflight.
	// (Errors here skip the no-store header, as in the Hono middleware.)
	if method != "GET" {
		if let Some(o) = req.header("origin").filter(|o| !o.is_empty())
			&& o != req.origin
		{
			return err(403, "forbidden_origin").into_resp();
		}
		if method != "DELETE" && !req.header("content-type").is_some_and(|t| t.starts_with("application/json")) {
			return err(415, "json_required").into_resp();
		}
	}
	let keys = match &env.keys {
		Ok(k) => k,
		Err(e) => return crate::http::Error::Internal(e.clone()).into_resp(),
	};

	let segs: Option<Vec<String>> = req.path[4..].split('/').skip(1).map(|s| percent_decode(s, false)).collect();
	let mut c = Ctx { env, db: &env.db, req, cfg, keys, now, user: None, session: None };
	let res = match segs {
		Some(segs) => dispatch(app, &mut c, method, &segs).await,
		None => Err(err(404, "not_found")),
	};
	let mut resp = res.unwrap_or_else(|e| e.into_resp());
	resp.set("cache-control", "no-store");
	if head {
		resp.body.clear();
	}
	resp
}

async fn dispatch<D: Db, A: App>(app: &A, c: &mut Ctx<'_, D>, m: &str, segs: &[String]) -> R<Resp> {
	let s: Vec<&str> = segs.iter().map(String::as_str).collect();
	match (m, s.as_slice()) {
		("GET", ["health"]) => return Ok(Resp::ok(json!({ "ok": true, "time": c.now }))),
		("POST", ["prelogin"]) => return prelogin(c).await,
		("POST", ["login"]) => return login(c).await,
		("POST", ["logout"]) => return logout(c).await,
		("GET", ["session"]) => {
			c.require_session().await?;
			return Ok(Resp::ok(account_response(c.user())));
		}
		("GET", ["setup"]) => return setup_status(c).await,
		("POST", ["setup"]) => return setup(c).await,
		("GET", ["invites", "check"]) => return invite_check(c).await,
		("POST", ["register"]) => return register(c).await,
		("POST", ["recover", "start"]) => return recover_start(c).await,
		("POST", ["recover", "finish"]) => return recover_finish(c).await,
		("POST", ["account", "password"]) => return change_password(c).await,
		("POST", ["account", "totp", "setup"]) => return totp_setup(c).await,
		("POST", ["account", "totp", "enable"]) => return totp_enable(c).await,
		("POST", ["account", "totp", "disable"]) => return totp_disable(c).await,
		_ => {}
	}
	if s.first() == Some(&"admin") {
		// app.use("/admin/*", requireSession, requireAdmin)
		c.require_session().await?;
		c.require_admin()?;
		if let Some(r) = admin(c, m, &s[1..]).await? {
			return Ok(r);
		}
		return Err(err(404, "not_found"));
	}
	match app.route(c, m, segs).await? {
		Some(r) => Ok(r),
		None => Err(err(404, "not_found")),
	}
}

// --- auth --------------------------------------------------------------------------------------------

const MIN: i64 = 60_000;

fn login_limits<D: Db>(c: &Ctx<'_, D>, u: &str, scope: &str) -> Vec<Limit> {
	vec![limit(format!("{scope}:u:{u}"), 10, 15 * MIN), limit(format!("{scope}:ip:{}", c.client_ip()), 30, 15 * MIN)]
}

fn ip_limit<D: Db>(c: &Ctx<'_, D>, scope: &str, max: i64) -> Vec<Limit> {
	vec![limit(format!("{scope}:ip:{}", c.client_ip()), max, 15 * MIN)]
}

async fn sign_in<D: Db>(c: &Ctx<'_, D>, user: &UserRow) -> R<Resp> {
	let (_, token) = session::create_session(c.db, &user.id, c.now).await?;
	Ok(Resp::ok(account_response(user)).with("set-cookie", &session::session_cookie(&token, c.cfg.cookie)))
}

fn totp_aad<D: Db>(c: &Ctx<'_, D>, user_id: &str) -> String {
	format!("{}/login-totp/v1/{user_id}", c.cfg.aad_prefix)
}

/// Accepts the current, previous or next 30 s step, and never the same step twice.
async fn check_login_totp<D: Db>(c: &Ctx<'_, D>, user: &UserRow, code: &str) -> R<bool> {
	let Some(enc) = &user.login_totp_secret_enc else { return Ok(false) };
	if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
		return Ok(false);
	}
	let sealed: Sealed = serde_json::from_str(enc).map_err(|e| crate::http::Error::Internal(format!("login_totp_secret_enc: {e}")))?;
	let secret = c.keys.open_secret(&sealed, &totp_aad(c, &user.id)).map_err(|e| crate::http::Error::Internal(e.to_string()))?;
	let key = base32_decode(&secret).map_err(|_| crate::http::Error::Internal("login TOTP secret is not base32".into()))?;
	let now = totp_counter(c.now, 30);
	for step in [now, now - 1, now + 1] {
		if step <= user.login_totp_last_counter {
			continue;
		}
		if hotp_sha1(&key, step as u64, 6) == code {
			let n =
				c.db.run(
					q("UPDATE users SET login_totp_last_counter = ? WHERE id = ? AND login_totp_last_counter < ?")
						.b(step)
						.b(&user.id)
						.b(step),
				)
				.await?;
			return Ok(n == 1);
		}
	}
	Ok(false)
}

const INSERT_COLUMNS: &str = "id, username, role, auth_verifier, kdf_salt, kdf_params, wrapped_vault_key, recovery_wrapped_key, recovery_verifier, created_at, updated_at";

/// Binds ?1..?10 in INSERT_COLUMNS order (role excluded).
fn bind_user(s: Stmt, id: &str, uname: &str, m: &AccountMaterial, keys: &ServerKeys, now: i64) -> Stmt {
	s.b(id)
		.b(uname)
		.b(keys.verifier(&m.pw.auth_key))
		.b(&m.pw.kdf.salt)
		.b(json_string(&m.pw.kdf))
		.b(json_string(&m.pw.wrapped_vault_key))
		.b(json_string(&m.recovery_wrapped_key))
		.b(keys.verifier(&m.recovery_auth_key))
		.b(now)
		.b(now)
}

/// `JSON.stringify`
pub fn json_string<T: serde::Serialize>(v: &T) -> String {
	serde_json::to_string(v).unwrap_or_default()
}

async fn prelogin<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let u = v::username(&c.body()?, "username")?;
	if let Some(user) = user_by_name(c.db, &u).await? {
		return Ok(Resp::ok(json!({ "kdf": parse_json(&user.kdf_params) })));
	}
	Ok(Resp::ok(json!({
		"kdf": { "alg": "pbkdf2-sha256", "iterations": DEFAULT_PBKDF2_ITERATIONS, "salt": c.keys.decoy_salt(&u) }
	})))
}

async fn login<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let b = c.body()?;
	let u = v::username(&b, "username")?;
	let auth_key = v::b64_bytes(&b, "authKey", 32)?;
	let totp = v::opt_str(&b, "totp", 16)?;
	let limits = login_limits(c, &u, "login");
	assert_not_limited(c.db, &limits, c.now).await?;
	let user = match user_by_name(c.db, &u).await? {
		Some(user) if c.keys.verify(&auth_key, &user.auth_verifier) => user,
		_ => {
			hit(c.db, &limits, c.now).await?;
			return Err(err_msg(401, "invalid_credentials", "Wrong username or password"));
		}
	};
	if user.disabled != 0 {
		return Err(err_msg(403, "account_disabled", "This account is disabled"));
	}
	if user.login_totp_enabled != 0 {
		let Some(code) = totp.filter(|t| !t.is_empty()) else {
			return Err(err_msg(401, "totp_required", "Enter the code from your authenticator"));
		};
		if !check_login_totp(c, &user, js_trim(&code)).await? {
			hit(c.db, &limits, c.now).await?;
			return Err(err_msg(401, "invalid_totp", "Wrong or reused code"));
		}
	}
	clear(c.db, &[limits[0].key.clone()]).await?;
	c.audit(Some(&user.id), "login", None).await?;
	sign_in(c, &user).await
}

async fn logout<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	if let Some(t) = session::read_session_cookie(c.req.header("cookie"), c.cfg.cookie)
		&& let Some(s) = session::find_session(c.db, &t, c.now).await?
	{
		session::delete_session(c.db, &s.id).await?;
	}
	Ok(Resp::ok_true().with("set-cookie", &session::clear_session_cookie(c.cfg.cookie)))
}

async fn setup_status<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let n = c.db.first(q("SELECT COUNT(*) AS n FROM users")).await?.map_or(0, |r| r.i("n"));
	Ok(Resp::ok(json!({ "needed": n == 0, "tokenConfigured": !c.env.admin_setup_token.is_empty() })))
}

/// First admin. Works only while there are no users, and only with ADMIN_SETUP_TOKEN.
async fn setup<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let limits = ip_limit(c, "setup", 10);
	assert_not_limited(c.db, &limits, c.now).await?;
	let b = c.body()?;
	let token = v::str_max(&b, "setupToken", 256)?;
	let expected = &c.env.admin_setup_token;
	if expected.is_empty() || crate::text::js_len(expected) < 32 || !v::timing_safe_eq_strings(&token, expected) {
		hit(c.db, &limits, c.now).await?;
		return Err(err(403, "invalid_setup_token"));
	}
	let u = v::username(&b, "username")?;
	let m = v::account_material(&b)?;
	let id = random_uuid();
	let stmt = q(&format!(
		"INSERT INTO users ({INSERT_COLUMNS}) SELECT ?1, ?2, 'admin', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
		 WHERE NOT EXISTS (SELECT 1 FROM users)"
	));
	if c.db.run(bind_user(stmt, &id, &u, &m, c.keys, c.now)).await? != 1 {
		return Err(err_msg(409, "already_set_up", "This server already has accounts"));
	}
	c.audit(Some(&id), "setup_admin", None).await?;
	let user = user_by_id(c.db, &id).await?.ok_or_else(|| crate::http::Error::Internal("new admin missing".into()))?;
	sign_in(c, &user).await
}

pub fn invite_hash(token: &str) -> String {
	to_b64(&sha256(token.as_bytes()))
}

async fn invite_check<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let limits = ip_limit(c, "invite", 20);
	assert_not_limited(c.db, &limits, c.now).await?;
	hit(c.db, &limits, c.now).await?;
	let token = c.req.query_param("token").unwrap_or_default();
	let row =
		c.db.first(
			q("SELECT expires_at FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?").b(invite_hash(&token)).b(c.now),
		)
		.await?;
	Ok(Resp::ok(json!({ "valid": row.is_some(), "expiresAt": row.map(|r| r.i("expires_at")) })))
}

async fn register<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let limits = ip_limit(c, "register", 20);
	assert_not_limited(c.db, &limits, c.now).await?;
	hit(c.db, &limits, c.now).await?;
	let b = c.body()?;
	let token_hash = invite_hash(&v::str_max(&b, "invite", 128)?);
	let u = v::username(&b, "username")?;
	let m = v::account_material(&b)?;
	let id = random_uuid();
	if user_by_name(c.db, &u).await?.is_some() {
		return Err(err_msg(409, "username_taken", "That username is taken"));
	}
	// One transaction: create the user only if the invite is unused and unexpired, then consume it.
	let ins = bind_user(
		q(&format!(
			"INSERT INTO users ({INSERT_COLUMNS})
			 SELECT ?1, ?2, i.role, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10 FROM invites i
			 WHERE i.token_hash = ?11 AND i.used_at IS NULL AND i.expires_at > ?9"
		)),
		&id,
		&u,
		&m,
		c.keys,
		c.now,
	)
	.b(&token_hash);
	let upd = q(
		"UPDATE invites SET used_at = ?1, used_by = ?2 WHERE token_hash = ?3 AND used_at IS NULL AND EXISTS (SELECT 1 FROM users WHERE id = ?2)",
	)
	.b(c.now)
	.b(&id)
	.b(&token_hash);
	let res = c.db.batch_(vec![ins, upd]).await?;
	if res.first().map_or(0, |r| r.changes) != 1 {
		return Err(err_msg(403, "invalid_invite", "This invite link is invalid, used or expired"));
	}
	c.audit(Some(&id), "register", None).await?;
	let user = user_by_id(c.db, &id).await?.ok_or_else(|| crate::http::Error::Internal("new user missing".into()))?;
	sign_in(c, &user).await
}

/// Recovery: prove possession of the recovery key.
async fn recovery_user<D: Db>(c: &Ctx<'_, D>, b: &Obj) -> R<UserRow> {
	let u = v::username(b, "username")?;
	let proof = v::b64_bytes(b, "recoveryAuthKey", 32)?;
	let limits = login_limits(c, &u, "recover");
	assert_not_limited(c.db, &limits, c.now).await?;
	let user = match user_by_name(c.db, &u).await? {
		Some(user) if c.keys.verify(&proof, &user.recovery_verifier) => user,
		_ => {
			hit(c.db, &limits, c.now).await?;
			return Err(err_msg(401, "invalid_recovery_key", "Wrong username or recovery key"));
		}
	};
	if user.disabled != 0 {
		return Err(err(403, "account_disabled"));
	}
	Ok(user)
}

async fn recover_start<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let user = recovery_user(c, &c.body()?).await?;
	Ok(Resp::ok(json!({ "recoveryWrappedKey": parse_json(&user.recovery_wrapped_key) })))
}

async fn recover_finish<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	let b = c.body()?;
	let user = recovery_user(c, &b).await?;
	let m = v::password_material(&b)?;
	c.db.batch_(vec![
		q("UPDATE users SET auth_verifier = ?, kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?,
			 login_totp_enabled = 0, login_totp_secret_enc = NULL, updated_at = ? WHERE id = ?")
		.b(c.keys.verifier(&m.auth_key))
		.b(&m.kdf.salt)
		.b(json_string(&m.kdf))
		.b(json_string(&m.wrapped_vault_key))
		.b(c.now)
		.b(&user.id),
		q("DELETE FROM sessions WHERE user_id = ?").b(&user.id),
	])
	.await?;
	c.audit(Some(&user.id), "recover", None).await?;
	let user = user_by_id(c.db, &user.id).await?.ok_or_else(|| crate::http::Error::Internal("user missing".into()))?;
	sign_in(c, &user).await
}

async fn change_password<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let b = c.body()?;
	let user = c.user().clone();
	if !c.keys.verify(&v::b64_bytes(&b, "currentAuthKey", 32)?, &user.auth_verifier) {
		return Err(err_msg(401, "invalid_credentials", "Current password is wrong"));
	}
	let m = v::password_material(&b)?;
	c.db.run(
		q("UPDATE users SET auth_verifier = ?, kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?, updated_at = ? WHERE id = ?")
			.b(c.keys.verifier(&m.auth_key))
			.b(&m.kdf.salt)
			.b(json_string(&m.kdf))
			.b(json_string(&m.wrapped_vault_key))
			.b(c.now)
			.b(&user.id),
	)
	.await?;
	session::delete_other_sessions(c.db, &user.id, &c.session().id).await?;
	c.audit(Some(&user.id), "password_change", None).await?;
	let user = user_by_id(c.db, &user.id).await?.ok_or_else(|| crate::http::Error::Internal("user missing".into()))?;
	Ok(Resp::ok(account_response(&user)))
}

// Login TOTP: setup stores a pending secret; enable confirms one code; disable needs the password.
async fn totp_setup<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let user = c.user().clone();
	if user.login_totp_enabled != 0 {
		return Err(bad("totp_already_enabled"));
	}
	let secret = base32_encode(&random_bytes(20), false);
	let sealed = c.keys.seal_secret(&secret, &totp_aad(c, &user.id));
	c.db.run(q("UPDATE users SET login_totp_secret_enc = ?, login_totp_last_counter = 0 WHERE id = ?").b(json_string(&sealed)).b(&user.id))
		.await?;
	let issuer = format!("{} ({})", c.cfg.app_name, c.req.host());
	let uri = otpauth_totp_uri(&issuer, &user.username, &secret);
	Ok(Resp::ok(json!({ "secret": secret, "uri": uri })))
}

async fn totp_enable<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let code = js_trim(&v::str_max(&c.body()?, "code", 16)?).to_string();
	let user = user_by_id(c.db, &c.user().id).await?.ok_or_else(|| crate::http::Error::Internal("user missing".into()))?;
	if user.login_totp_enabled != 0 {
		return Err(bad("totp_already_enabled"));
	}
	if !check_login_totp(c, &user, &code).await? {
		return Err(err_msg(400, "invalid_totp", "Wrong code. Check the time on your device."));
	}
	c.db.run(q("UPDATE users SET login_totp_enabled = 1 WHERE id = ?").b(&user.id)).await?;
	c.audit(Some(&user.id), "totp_enable", None).await?;
	Ok(Resp::ok_true())
}

async fn totp_disable<D: Db>(c: &mut Ctx<'_, D>) -> R<Resp> {
	c.require_session().await?;
	let user = c.user().clone();
	if !c.keys.verify(&v::b64_bytes(&c.body()?, "authKey", 32)?, &user.auth_verifier) {
		return Err(err_msg(401, "invalid_credentials", "Password is wrong"));
	}
	c.db.run(q("UPDATE users SET login_totp_enabled = 0, login_totp_secret_enc = NULL WHERE id = ?").b(&user.id)).await?;
	c.audit(Some(&user.id), "totp_disable", None).await?;
	Ok(Resp::ok_true())
}

// --- admin: single-use invite links. The token is shown once; only its hash is stored. ---------------

const HOUR: i64 = 3_600_000;

async fn admin<D: Db>(c: &mut Ctx<'_, D>, m: &str, s: &[&str]) -> R<Option<Resp>> {
	Ok(Some(match (m, s) {
		("POST", ["invites"]) => {
			let b = c.body()?;
			let role = if b.contains_key("role") { v::str_max(&b, "role", 8)? } else { "user".into() };
			if role != "user" && role != "admin" {
				return Err(err(400, "invalid_role"));
			}
			let hours = if b.contains_key("ttlHours") { v::int(&b, "ttlHours", 1, 24 * 14)? } else { 24 };
			let token = to_b64url(&random_bytes(32));
			let id = random_uuid();
			let me = c.user().id.clone();
			c.db.run(
				q("INSERT INTO invites (id, token_hash, role, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
					.b(&id)
					.b(invite_hash(&token))
					.b(&role)
					.b(&me)
					.b(c.now)
					.b(c.now + hours * HOUR),
			)
			.await?;
			c.audit(Some(&me), "invite_create", Some(json!({ "inviteId": id, "role": role }))).await?;
			Resp::ok(json!({ "id": id, "token": token, "role": role, "expiresAt": c.now + hours * HOUR }))
		}
		("GET", ["invites"]) => {
			let rows =
				c.db.all(q(
					"SELECT i.id, i.role, i.created_at AS createdAt, i.expires_at AS expiresAt, i.used_at AS usedAt, u.username AS usedBy
					 FROM invites i LEFT JOIN users u ON u.id = i.used_by ORDER BY i.created_at DESC LIMIT 100",
				))
				.await?;
			Resp::ok(json!({ "invites": rows }))
		}
		("DELETE", ["invites", id]) => {
			c.db.run(q("DELETE FROM invites WHERE id = ? AND used_at IS NULL").b(*id)).await?;
			Resp::ok_true()
		}
		("GET", ["users"]) => {
			let rows =
				c.db.all(q("SELECT id, username, role, disabled, login_totp_enabled AS totpEnabled, created_at AS createdAt
					 FROM users ORDER BY created_at"))
					.await?;
			Resp::ok(json!({ "users": rows }))
		}
		_ => return Ok(None),
	}))
}
