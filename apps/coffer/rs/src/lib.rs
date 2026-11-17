//! Coffer API in Rust: a port of `apps/coffer/worker` (dashboard API with session cookies, and the
//! machine REST API `/api/v1` used by the SDKs). Same routes, SQL, status codes and JSON.
//!
//! The cookie name and AAD prefix must not change once deployed.

mod common;
mod machine;
mod projects;
mod secrets;

use cfsa_core::accounts::{AccountsConfig, App, Ctx};
use cfsa_core::db::Db;
use cfsa_core::http::{R, Resp};

pub struct Coffer;

pub static CONFIG: AccountsConfig = AccountsConfig { app_name: "Coffer", cookie: "__Host-coffer_session", aad_prefix: "coffer" };

/// Embedded `apps/coffer/migrations`, applied by the standalone server (on D1 the installer applies them).
pub static MIGRATIONS: &[(&str, &str)] = &[("0001_init.sql", include_str!("../../migrations/0001_init.sql"))];

impl App for Coffer {
	fn config(&self) -> &AccountsConfig {
		&CONFIG
	}

	async fn route<D: Db>(&self, c: &mut Ctx<'_, D>, m: &str, segs: &[String]) -> R<Option<Resp>> {
		let s: Vec<&str> = segs.iter().map(String::as_str).collect();
		if s.first() == Some(&"v1") {
			return machine::route(c, m, &s[1..]).await;
		}
		// app.use(p, requireSession) for "/keys", "/users/*", "/projects", "/projects/*", "/environments/*",
		// "/identities/*" ("/x/*" also matches "/x").
		let session = match s.as_slice() {
			["keys"] => true,
			[first, ..] => matches!(*first, "users" | "projects" | "environments" | "identities"),
			[] => false,
		};
		if !session {
			return Ok(None);
		}
		c.require_session().await?;
		projects::route(c, m, &s).await
	}
}

#[cfg(target_arch = "wasm32")]
#[worker::event(fetch)]
async fn fetch(req: worker::Request, env: worker::Env, _ctx: worker::Context) -> worker::Result<worker::Response> {
	cfsa_core::worker_glue::fetch(&Coffer, req, env).await
}

#[cfg(test)]
mod tests {
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
}
