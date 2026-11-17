//! Platform-neutral request/response and the API error type (`HttpError` in server-kit).

use crate::db::DbError;
use serde_json::{Map, Value, json};

/// An API request as the Worker sees it.
#[derive(Clone, Debug, Default)]
pub struct Req {
	pub method: String,
	/// Public origin, e.g. `https://tumbler.example.com` (`new URL(req.url).origin`).
	pub origin: String,
	/// Raw path, e.g. `/api/sync`.
	pub path: String,
	/// Raw query string without `?`.
	pub query: String,
	/// Header names lowercase.
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
	/// `CF-Connecting-IP` on Workers; the proxy-derived address natively.
	pub client_ip: String,
}

impl Req {
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
	}

	pub fn query_param(&self, name: &str) -> Option<String> {
		crate::text::query_get(&self.query, name)
	}

	/// `new URL(req.url).host`.
	pub fn host(&self) -> &str {
		self.origin.split_once("://").map_or(self.origin.as_str(), |(_, h)| h)
	}
}

#[derive(Clone, Debug)]
pub struct Resp {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

impl Resp {
	pub fn json(status: u16, v: &Value) -> Resp {
		Resp { status, headers: vec![("content-type".into(), "application/json".into())], body: serde_json::to_vec(v).unwrap_or_default() }
	}

	pub fn ok(v: Value) -> Resp {
		Resp::json(200, &v)
	}

	/// `{ ok: true }`
	pub fn ok_true() -> Resp {
		Resp::ok(json!({ "ok": true }))
	}

	pub fn text(status: u16, s: &str) -> Resp {
		Resp { status, headers: vec![("content-type".into(), "text/plain; charset=UTF-8".into())], body: s.as_bytes().to_vec() }
	}

	/// Sets a header, replacing any with the same name.
	pub fn set(&mut self, k: &str, v: &str) {
		self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
		self.headers.push((k.to_ascii_lowercase(), v.to_string()));
	}

	pub fn with(mut self, k: &str, v: &str) -> Resp {
		self.set(k, v);
		self
	}
}

#[derive(Debug)]
pub struct HttpError {
	pub status: u16,
	pub code: String,
	pub message: String,
	pub extra: Map<String, Value>,
}

#[derive(Debug)]
pub enum Error {
	/// Boxed: keeps `R<T>` small on the happy path.
	Http(Box<HttpError>),
	Internal(String),
}

pub type R<T> = Result<T, Error>;

/// `new HttpError(status, code)`: the message defaults to the code.
pub fn err(status: u16, code: &str) -> Error {
	err_msg(status, code, code)
}

pub fn err_msg(status: u16, code: &str, message: &str) -> Error {
	Error::Http(Box::new(HttpError { status, code: code.into(), message: message.into(), extra: Map::new() }))
}

/// `bad(code, message?)`: 400.
pub fn bad(code: &str) -> Error {
	err(400, code)
}

pub fn bad_msg(code: &str, message: &str) -> Error {
	err_msg(400, code, message)
}

impl From<DbError> for Error {
	fn from(e: DbError) -> Self {
		Error::Internal(format!("D1/SQLite: {e}"))
	}
}

impl Error {
	/// The `app.onError` handler.
	pub fn into_resp(self) -> Resp {
		match self {
			Error::Http(e) => {
				let e = *e;
				let mut body = Map::new();
				body.insert("error".into(), Value::from(e.code));
				body.insert("message".into(), Value::from(e.message));
				let retry = e.extra.get("retryAfter").and_then(Value::as_i64);
				body.extend(e.extra);
				let mut r = Resp::json(e.status, &Value::Object(body));
				if e.status == 429
					&& let Some(s) = retry
				{
					r.set("retry-after", &s.to_string());
				}
				r
			}
			Error::Internal(msg) => {
				crate::log_error(&msg);
				Resp::json(500, &json!({ "error": "internal_error" }))
			}
		}
	}
}
