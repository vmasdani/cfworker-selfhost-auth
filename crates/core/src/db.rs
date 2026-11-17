//! The D1 subset the apps use, as a trait: D1 on Workers, SQLite natively.
//!
//! Statements bind positional (`?`) or numbered (`?N`) parameters. Rows are JSON objects in column
//! order, like D1's `results`. `changes` is 0 for statements that only read (as D1 reports).

use crate::http::Error;
use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
	Null,
	Int(i64),
	Text(String),
}

impl From<i64> for Val {
	fn from(v: i64) -> Self {
		Val::Int(v)
	}
}
impl From<&str> for Val {
	fn from(v: &str) -> Self {
		Val::Text(v.to_string())
	}
}
impl From<&String> for Val {
	fn from(v: &String) -> Self {
		Val::Text(v.clone())
	}
}
impl From<String> for Val {
	fn from(v: String) -> Self {
		Val::Text(v)
	}
}
impl<T: Into<Val>> From<Option<T>> for Val {
	fn from(v: Option<T>) -> Self {
		v.map_or(Val::Null, Into::into)
	}
}

#[derive(Clone, Debug)]
pub struct Stmt {
	pub sql: String,
	pub params: Vec<Val>,
}

/// Starts a statement: `q("SELECT ... WHERE id = ?").b(id)`.
pub fn q(sql: &str) -> Stmt {
	Stmt { sql: sql.to_string(), params: Vec::new() }
}

impl Stmt {
	pub fn b(mut self, v: impl Into<Val>) -> Self {
		self.params.push(v.into());
		self
	}
}

pub type Row = Map<String, Value>;

#[derive(Debug, Default)]
pub struct Exec {
	pub rows: Vec<Row>,
	pub changes: u64,
}

/// A database error; the message keeps the engine's text (e.g. "UNIQUE constraint failed: ...").
#[derive(Debug)]
pub struct DbError(pub String);

impl std::fmt::Display for DbError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl DbError {
	pub fn is_unique(&self) -> bool {
		self.0.contains("UNIQUE")
	}
}

#[allow(async_fn_in_trait)]
pub trait Db {
	async fn exec(&self, s: Stmt) -> Result<Exec, DbError>;
	/// All statements in one transaction: all apply or none.
	async fn batch(&self, s: Vec<Stmt>) -> Result<Vec<Exec>, DbError>;
}

/// Convenience calls on any [`Db`], with errors mapped to internal server errors.
#[allow(async_fn_in_trait)]
pub trait DbExt: Db {
	async fn first(&self, s: Stmt) -> Result<Option<Row>, Error> {
		Ok(self.exec(s).await?.rows.into_iter().next())
	}
	async fn all(&self, s: Stmt) -> Result<Vec<Row>, Error> {
		Ok(self.exec(s).await?.rows)
	}
	async fn run(&self, s: Stmt) -> Result<u64, Error> {
		Ok(self.exec(s).await?.changes)
	}
	async fn batch_(&self, s: Vec<Stmt>) -> Result<Vec<Exec>, Error> {
		Ok(self.batch(s).await?)
	}
}

impl<T: Db + ?Sized> DbExt for T {}

/// Typed access to row columns; missing or mistyped columns read as empty/zero/None.
pub trait RowExt {
	fn s(&self, k: &str) -> String;
	fn os(&self, k: &str) -> Option<String>;
	fn i(&self, k: &str) -> i64;
	fn oi(&self, k: &str) -> Option<i64>;
}

impl RowExt for Row {
	fn s(&self, k: &str) -> String {
		self.os(k).unwrap_or_default()
	}
	fn os(&self, k: &str) -> Option<String> {
		self.get(k).and_then(Value::as_str).map(str::to_string)
	}
	fn i(&self, k: &str) -> i64 {
		self.oi(k).unwrap_or(0)
	}
	fn oi(&self, k: &str) -> Option<i64> {
		self.get(k).and_then(|v| v.as_i64().or_else(|| v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)))
	}
}

/// D1 returns numbers as JS doubles; turn integral ones back into JSON integers.
pub fn normalize_numbers(v: &mut Value) {
	match v {
		Value::Number(n) if n.is_f64() => {
			if let Some(f) = n.as_f64()
				&& f.fract() == 0.0
				&& f.abs() <= 9_007_199_254_740_991.0
			{
				*v = Value::from(f as i64);
			}
		}
		Value::Array(a) => a.iter_mut().for_each(normalize_numbers),
		Value::Object(o) => o.values_mut().for_each(normalize_numbers),
		_ => {}
	}
}
