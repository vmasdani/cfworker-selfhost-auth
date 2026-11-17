//! Workers runtime adapter (wasm32 only): D1 as a [`Db`], and `fetch` for an [`App`].

use crate::accounts::{App, Env, serve};
use crate::db::{Db, DbError, Exec, Row, Stmt, Val, normalize_numbers};
use crate::http::Req;
use worker::wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement, D1Result, Headers, Request, Response};

pub struct D1(pub D1Database);

fn js(v: &Val) -> JsValue {
	match v {
		Val::Null => JsValue::NULL,
		Val::Int(i) => JsValue::from_f64(*i as f64),
		Val::Text(s) => JsValue::from_str(s),
	}
}

fn e(err: worker::Error) -> DbError {
	DbError(err.to_string())
}

impl D1 {
	fn prepare(&self, s: &Stmt) -> Result<D1PreparedStatement, DbError> {
		let vals: Vec<JsValue> = s.params.iter().map(js).collect();
		self.0.prepare(s.sql.as_str()).bind(&vals).map_err(e)
	}
}

fn convert(r: &D1Result) -> Result<Exec, DbError> {
	if let Some(msg) = r.error() {
		return Err(DbError(msg));
	}
	let mut rows: Vec<Row> = r.results::<Row>().map_err(e)?;
	for row in rows.iter_mut() {
		row.values_mut().for_each(normalize_numbers);
	}
	let changes = r.meta().map_err(e)?.and_then(|m| m.changes).unwrap_or(0) as u64;
	Ok(Exec { rows, changes })
}

impl Db for D1 {
	async fn exec(&self, s: Stmt) -> Result<Exec, DbError> {
		let r = self.prepare(&s)?.all().await.map_err(e)?;
		convert(&r)
	}

	async fn batch(&self, s: Vec<Stmt>) -> Result<Vec<Exec>, DbError> {
		let stmts = s.iter().map(|x| self.prepare(x)).collect::<Result<Vec<_>, _>>()?;
		self.0.batch(stmts).await.map_err(e)?.iter().map(convert).collect()
	}
}

/// The Worker `fetch` handler for an app: bindings DB, SERVER_SECRET and ADMIN_SETUP_TOKEN.
/// Static assets are served by the assets layer; only `/api/*` reaches the Worker.
pub async fn fetch<A: App>(app: &A, mut req: Request, env: worker::Env) -> worker::Result<Response> {
	let url = req.url()?;
	let method = req.method().to_string();
	let headers: Vec<(String, String)> = req.headers().entries().map(|(k, v)| (k.to_ascii_lowercase(), v)).collect();
	let body = if method == "GET" || method == "HEAD" { Vec::new() } else { req.bytes().await.unwrap_or_default() };
	let client_ip = headers.iter().find(|(k, _)| k == "cf-connecting-ip").map_or("local".to_string(), |(_, v)| v.clone());
	let r = Req {
		method,
		origin: url.origin().ascii_serialization(),
		path: url.path().to_string(),
		query: url.query().unwrap_or("").to_string(),
		headers,
		body,
		client_ip,
	};
	let secret = env.secret("SERVER_SECRET").map(|s| s.to_string()).unwrap_or_default();
	let token = env.secret("ADMIN_SETUP_TOKEN").map(|s| s.to_string()).unwrap_or_default();
	let a = Env::new(D1(env.d1("DB")?), &secret, token);
	let out = serve(app, &a, &r, crate::now_ms()).await;

	let h = Headers::new();
	for (k, v) in &out.headers {
		h.append(k, v)?;
	}
	Ok(Response::from_bytes(out.body)?.with_status(out.status).with_headers(h))
}
