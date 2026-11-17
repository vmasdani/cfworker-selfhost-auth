//! The standalone HTTP server (port of `packages/standalone/src/server.ts`). One process per app, behind
//! a TLS reverse proxy (Caddy, nginx, Cloudflare Tunnel), under pm2 (fork mode) or systemd.
//!
//! Configuration (environment, plus `.env` files in the working directory as Bun loads them):
//!   PORT              listen port (default: the app's)
//!   HOST              listen address (default 127.0.0.1: only the reverse proxy can connect)
//!   DATA_DIR          database and generated secrets (default ./data)
//!   DATABASE_PATH     SQLite file (default $DATA_DIR/<app>.sqlite)
//!   PUBLIC_URL        public origin, e.g. https://tumbler.example.com. Used for the same-origin (CSRF)
//!                     check and the login TOTP issuer. Strongly recommended behind a proxy.
//!   TRUST_PROXY       1/0: take the client IP (rate limits) and, without PUBLIC_URL, the origin from
//!                     X-Forwarded-* headers. Default: 1 when HOST is a loopback address, else 0.
//!   CLIENT_IP_HEADER  header holding the client IP instead of X-Forwarded-For, e.g. CF-Connecting-IP
//!                     behind Cloudflare Tunnel. Only read when TRUST_PROXY is on.
//!   SERVER_SECRET     default: generated once into $DATA_DIR/server-secret (0600). Never change it.
//!   ADMIN_SETUP_TOKEN default: while there are no users, a fresh one is written on every start to
//!                     $DATA_DIR/admin-setup-token (0600) and removed once the first admin exists.
//!   STATIC_DIR        built web app (default: `dist` next to the executable, else ./dist)

use crate::dotenv::Config;
use crate::sqlite::SqliteDb;
use crate::static_site::StaticSite;
use bytes::Bytes;
use cfsa_core::accounts::{App, Env, serve};
use cfsa_core::crypto::{random_bytes, to_b64url};
use cfsa_core::http::{Req, Resp};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

pub struct Options {
	/// Short name: database file name and log prefix, e.g. "tumbler".
	pub name: &'static str,
	pub default_port: u16,
	/// Shown in the first-admin hint, e.g. "tumbler" for `./install.sh setup-admin --app tumbler`.
	pub installer_app: &'static str,
	/// Embedded `apps/<app>/migrations/*.sql` as (file name, SQL).
	pub migrations: &'static [(&'static str, &'static str)],
}

const MAX_BODY: usize = 16 * 1024 * 1024;
/// pm2 `kill_timeout` is 10 s; finish open requests well within it.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

fn is_loopback(h: &str) -> bool {
	matches!(h, "127.0.0.1" | "::1" | "localhost")
}

fn flag(v: Option<&str>, fallback: bool) -> bool {
	match v {
		None => fallback,
		Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
	}
}

fn write_private(path: &Path, value: &str) -> std::io::Result<()> {
	let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
	std::io::Write::write_all(&mut f, format!("{value}\n").as_bytes())?;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// `new URL(u).origin`: scheme and host lowercased, default port dropped.
pub fn origin_of(u: &str) -> Option<String> {
	let (scheme, rest) = u.trim().split_once("://")?;
	let scheme = scheme.to_ascii_lowercase();
	let authority = rest.split(['/', '?', '#']).next()?;
	let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h).to_ascii_lowercase();
	if host.is_empty() || !matches!(scheme.as_str(), "http" | "https") {
		return None;
	}
	let host = match scheme.as_str() {
		"https" => host.strip_suffix(":443").map(str::to_string).unwrap_or(host),
		_ => host.strip_suffix(":80").map(str::to_string).unwrap_or(host),
	};
	Some(format!("{scheme}://{host}"))
}

struct State<A: App> {
	app: A,
	env: Env<SqliteDb>,
	site: StaticSite,
	trust_proxy: bool,
	fixed_origin: Option<String>,
	client_ip_header: Option<String>,
	local_origin: String,
}

fn header<'a>(req: &'a hyper::Request<Incoming>, name: &str) -> Option<&'a str> {
	req.headers().get(name).and_then(|v| v.to_str().ok())
}

impl<A: App> State<A> {
	fn client_ip(&self, req: &hyper::Request<Incoming>, peer: SocketAddr) -> String {
		if self.trust_proxy {
			let v = match &self.client_ip_header {
				Some(h) => header(req, h).map(|v| v.trim().to_string()),
				None => header(req, "x-forwarded-for").and_then(|v| v.split(',').next_back()).map(|v| v.trim().to_string()),
			};
			if let Some(v) = v.filter(|v| !v.is_empty()) {
				return v;
			}
		}
		peer.ip().to_canonical().to_string()
	}

	fn public_origin(&self, req: &hyper::Request<Incoming>) -> String {
		if let Some(o) = &self.fixed_origin {
			return o.clone();
		}
		let host = header(req, "host");
		if self.trust_proxy {
			let proto = header(req, "x-forwarded-proto").and_then(|v| v.split(',').next()).map(str::trim);
			let fwd_host = header(req, "x-forwarded-host").and_then(|v| v.split(',').next()).map(str::trim).or(host);
			if let (Some(p @ ("http" | "https")), Some(h)) = (proto, fwd_host) {
				return format!("{p}://{h}");
			}
		}
		host.and_then(|h| origin_of(&format!("http://{h}"))).unwrap_or_else(|| self.local_origin.clone())
	}
}

fn to_hyper(r: Resp) -> hyper::Response<Full<Bytes>> {
	let mut b = hyper::Response::builder().status(r.status);
	for (k, v) in &r.headers {
		b = b.header(k.as_str(), v.as_str());
	}
	b.body(Full::new(Bytes::from(r.body))).unwrap_or_else(|_| {
		let mut res = hyper::Response::new(Full::new(Bytes::from_static(br#"{"error":"internal_error"}"#)));
		*res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
		res
	})
}

async fn handle<A: App>(
	st: Rc<State<A>>,
	req: hyper::Request<Incoming>,
	peer: SocketAddr,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
	let method = req.method().as_str().to_string();
	let path = req.uri().path().to_string();
	if path != "/api" && !path.starts_with("/api/") {
		let inm = header(&req, "if-none-match").map(str::to_string);
		let ae = header(&req, "accept-encoding").unwrap_or("").to_string();
		let r = st.site.respond(&method, &path, inm.as_deref(), &ae).unwrap_or_else(|| {
			// Bun's `new Response("Not found")`
			Resp::text(if method == "GET" || method == "HEAD" { 404 } else { 405 }, "Not found")
				.with("content-type", "text/plain;charset=utf-8")
		});
		return Ok(to_hyper(r));
	}
	// Rebuild the request as the Worker would see it: public origin, and the client IP in place of
	// CF-Connecting-IP (a client-sent CF-Connecting-IP is never trusted unless it is CLIENT_IP_HEADER).
	let client_ip = st.client_ip(&req, peer);
	let origin = st.public_origin(&req);
	let query = req.uri().query().unwrap_or("").to_string();
	let headers: Vec<(String, String)> =
		req.headers().iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string()))).collect();
	let body = if method == "GET" || method == "HEAD" {
		Vec::new()
	} else {
		match Limited::new(req.into_body(), MAX_BODY).collect().await {
			Ok(b) => b.to_bytes().to_vec(),
			Err(_) => return Ok(to_hyper(Resp::text(413, "Payload Too Large"))),
		}
	};
	let head = method == "HEAD";
	let r = Req { method, origin, path, query, headers, body, client_ip };
	let mut out = serve(&st.app, &st.env, &r, cfsa_core::now_ms()).await;
	if head {
		// hyper omits it for an empty HEAD body; Bun sends 0 like Workers.
		out.set("content-length", "0");
	}
	Ok(to_hyper(out))
}

fn static_dir(cfg: &Config) -> PathBuf {
	if let Some(d) = cfg.get("STATIC_DIR") {
		return PathBuf::from(d);
	}
	let beside = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.join("dist")));
	match beside {
		Some(d) if d.join("index.html").exists() => d,
		_ => PathBuf::from("dist"),
	}
}

/// Runs the server until SIGINT/SIGTERM. Exits the process on fatal startup errors.
pub fn run<A: App + 'static>(app: A, o: Options) {
	let log = move |m: &str| println!("[{}] {m}", o.name);
	if let Err(e) = start(app, &o, &log) {
		eprintln!("[{}] fatal: {e}", o.name);
		std::process::exit(1);
	}
}

fn start<A: App + 'static>(app: A, o: &Options, log: &dyn Fn(&str)) -> Result<(), String> {
	let cfg = Config::load();
	let data_dir = std::path::absolute(cfg.get("DATA_DIR").unwrap_or("data")).map_err(|e| e.to_string())?;
	std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
	let db_path = match cfg.get("DATABASE_PATH") {
		Some(p) => std::path::absolute(p).map_err(|e| e.to_string())?,
		None => data_dir.join(format!("{}.sqlite", o.name)),
	};
	let host = cfg.get("HOST").unwrap_or("127.0.0.1").to_string();
	let port: u16 = match cfg.get("PORT") {
		Some(p) => p.parse().map_err(|_| format!("invalid PORT: {p}"))?,
		None => o.default_port,
	};
	let trust_proxy = flag(cfg.get("TRUST_PROXY"), is_loopback(&host));
	let fixed_origin = match cfg.get("PUBLIC_URL") {
		Some(u) => Some(origin_of(u).ok_or_else(|| format!("invalid PUBLIC_URL: {u}"))?),
		None => None,
	};

	let sdir = static_dir(&cfg);
	if !sdir.join("index.html").exists() {
		return Err(format!("No built web app in {}. Run: bun run build:standalone (or set STATIC_DIR)", sdir.display()));
	}
	if let Some(fo) = &fixed_origin {
		let h = fo.split_once("://").map_or("", |(_, h)| h);
		let hostname = h.rsplit_once(':').map_or(h, |(n, _)| n).trim_matches(['[', ']']);
		if fo.starts_with("http:") && !is_loopback(hostname) {
			log("warning: PUBLIC_URL is plain http. Browsers only keep the __Host- session cookie over https; put a TLS proxy in front.");
		}
	}

	let db = SqliteDb::open(&db_path.to_string_lossy()).map_err(|e| format!("{}: {e}", db_path.display()))?;
	crate::migrate::migrate(&db, o.migrations, log)?;

	let secret = match cfg.get("SERVER_SECRET") {
		Some(s) => s.to_string(),
		None => {
			let p = data_dir.join("server-secret");
			if !p.exists() {
				write_private(&p, &to_b64url(&random_bytes(32))).map_err(|e| format!("{}: {e}", p.display()))?;
				log(&format!("generated SERVER_SECRET in {} (back it up with the database; every login depends on it)", p.display()));
			}
			std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?.trim().to_string()
		}
	};
	if cfsa_core::text::js_len(&secret) < 32 {
		return Err("SERVER_SECRET must be at least 32 characters".into());
	}
	let token_path = data_dir.join("admin-setup-token");
	let users: i64 = db.with(|c| c.query_row("SELECT COUNT(*) AS n FROM users", [], |r| r.get(0))).map_err(|e| e.to_string())?;
	let env_token = cfg.get("ADMIN_SETUP_TOKEN").map(str::to_string);
	let mut token = env_token.clone().unwrap_or_default();
	if users > 0 {
		let _ = std::fs::remove_file(&token_path);
	} else if token.is_empty() {
		token = to_b64url(&random_bytes(32));
		write_private(&token_path, &token).map_err(|e| format!("{}: {e}", token_path.display()))?;
	}

	let site = StaticSite::load(&sdir)?;
	let state = Rc::new(State {
		app,
		env: Env::new(db, &secret, token),
		site,
		trust_proxy,
		fixed_origin: fixed_origin.clone(),
		client_ip_header: cfg.get("CLIENT_IP_HEADER").map(|h| h.to_ascii_lowercase()),
		local_origin: format!("http://localhost:{port}"),
	});

	let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
	let local = tokio::task::LocalSet::new();
	local.block_on(&rt, async move {
		let addr = format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.clone() });
		let listener = tokio::net::TcpListener::bind(&addr).await.map_err(|e| format!("listen {addr}: {e}"))?;
		let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
		log(&format!(
			"listening on http://{host}:{bound} (database {}{})",
			db_path.display(),
			fixed_origin.as_ref().map(|o| format!(", public {o}")).unwrap_or_default()
		));
		if users == 0 {
			let url = fixed_origin.clone().unwrap_or_else(|| format!("http://localhost:{bound}"));
			let prefix = o.installer_app.to_uppercase();
			log(&if env_token.is_some() {
				format!(
					"no users yet: create the first admin with {prefix}_SETUP_TOKEN=<ADMIN_SETUP_TOKEN> ./install.sh setup-admin --app {} --url {url}",
					o.installer_app
				)
			} else {
				format!(
					"no users yet: create the first admin with {prefix}_SETUP_TOKEN=\"$(cat {})\" ./install.sh setup-admin --app {} --url {url}",
					token_path.display(),
					o.installer_app
				)
			});
		}

		let graceful = hyper_util::server::graceful::GracefulShutdown::new();
		let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
		let signal = loop {
			tokio::select! {
				r = listener.accept() => {
					let Ok((stream, peer)) = r else { continue };
					let st = state.clone();
					let conn = http1::Builder::new()
						.keep_alive(true)
						.serve_connection(TokioIo::new(stream), service_fn(move |req| handle(st.clone(), req, peer)));
					let conn = graceful.watch(conn);
					tokio::task::spawn_local(async move {
						let _ = conn.await;
					});
				}
				_ = tokio::signal::ctrl_c() => break "SIGINT",
				_ = sigterm.recv() => break "SIGTERM",
			}
		};
		log(&format!("{signal}: finishing open requests"));
		drop(listener);
		let _ = tokio::time::timeout(SHUTDOWN_GRACE, graceful.shutdown()).await;
		state.env.db.close();
		Ok::<(), String>(())
	})
}

#[cfg(test)]
mod tests {
	use super::origin_of;

	#[test]
	fn origins() {
		assert_eq!(origin_of("https://Coffer.Example.com:443/x?y").as_deref(), Some("https://coffer.example.com"));
		assert_eq!(origin_of("http://localhost:8702").as_deref(), Some("http://localhost:8702"));
		assert_eq!(origin_of("ftp://x"), None);
		assert_eq!(origin_of("nope"), None);
	}
}
