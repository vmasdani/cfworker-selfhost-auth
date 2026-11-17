//! Platform-independent backend core, ported from `packages/{crypto,totp,server-kit,worker-accounts}`.
//!
//! An app implements [`accounts::App`] and is served by [`accounts::serve`] over any [`db::Db`]:
//! D1 on Workers (see [`worker_glue`]) or SQLite natively (`cfsa-standalone`).

pub mod accounts;
pub mod crypto;
pub mod db;
pub mod http;
pub mod keys;
pub mod rate_limit;
pub mod session;
pub mod text;
pub mod totp;
pub mod validate;

#[cfg(target_arch = "wasm32")]
pub mod worker_glue;

/// Unix time in milliseconds (`Date.now()`).
pub fn now_ms() -> i64 {
	#[cfg(target_arch = "wasm32")]
	{
		js_sys::Date::now() as i64
	}
	#[cfg(not(target_arch = "wasm32"))]
	{
		std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
	}
}

/// Logs an unexpected error (`console.error` on Workers, stderr natively).
pub fn log_error(msg: &str) {
	#[cfg(target_arch = "wasm32")]
	worker::console_error!("{}", msg);
	#[cfg(not(target_arch = "wasm32"))]
	eprintln!("{msg}");
}
