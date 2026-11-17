//! SQLite as a [`Db`], with the semantics of `packages/standalone/src/d1.ts`: WAL, foreign keys on,
//! `batch` in one transaction, `changes` 0 for read-only statements.

use cfsa_core::db::{Db, DbError, Exec, Row, Stmt, Val};
use rusqlite::types::{ToSqlOutput, ValueRef};
use rusqlite::{Connection, ToSql};
use serde_json::Value;
use std::cell::RefCell;

/// One connection, used from a single thread (the server runs on a current-thread runtime).
pub struct SqliteDb {
	conn: RefCell<Connection>,
}

struct P<'a>(&'a Val);

impl ToSql for P<'_> {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(match self.0 {
			Val::Null => ToSqlOutput::Borrowed(ValueRef::Null),
			Val::Int(i) => ToSqlOutput::Borrowed(ValueRef::Integer(*i)),
			Val::Text(s) => ToSqlOutput::Borrowed(ValueRef::Text(s.as_bytes())),
		})
	}
}

fn e(err: rusqlite::Error) -> DbError {
	DbError(err.to_string())
}

fn json(v: ValueRef<'_>) -> Value {
	match v {
		ValueRef::Null => Value::Null,
		ValueRef::Integer(i) => Value::from(i),
		ValueRef::Real(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
		ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
		ValueRef::Blob(b) => Value::from(b.to_vec()),
	}
}

impl SqliteDb {
	pub fn open(path: &str) -> Result<SqliteDb, DbError> {
		let conn = Connection::open(path).map_err(e)?;
		conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;")
			.map_err(e)?;
		conn.set_prepared_statement_cache_capacity(64);
		Ok(SqliteDb { conn: RefCell::new(conn) })
	}

	/// For setup code (migrations, counts) that needs the raw connection.
	pub fn with<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
		f(&self.conn.borrow())
	}

	fn run(conn: &Connection, s: &Stmt) -> Result<Exec, DbError> {
		let mut st = conn.prepare_cached(&s.sql).map_err(e)?;
		if st.parameter_count() != s.params.len() {
			return Err(DbError(format!("wrong number of bindings: expected {}, got {}", st.parameter_count(), s.params.len())));
		}
		for (i, p) in s.params.iter().enumerate() {
			st.raw_bind_parameter(i + 1, P(p)).map_err(e)?;
		}
		let readonly = st.readonly();
		let cols: Vec<String> = st.column_names().into_iter().map(str::to_string).collect();
		let mut out = Vec::new();
		let mut rows = st.raw_query();
		while let Some(r) = rows.next().map_err(e)? {
			let mut row = Row::new();
			for (i, c) in cols.iter().enumerate() {
				row.insert(c.clone(), json(r.get_ref(i).map_err(e)?));
			}
			out.push(row);
		}
		drop(rows);
		let changes = if readonly { 0 } else { conn.changes() };
		Ok(Exec { rows: out, changes })
	}

	/// `PRAGMA optimize` before closing, as the Bun adapter does.
	pub fn close(&self) {
		let _ = self.conn.borrow().execute_batch("PRAGMA optimize");
	}
}

impl Db for SqliteDb {
	async fn exec(&self, s: Stmt) -> Result<Exec, DbError> {
		SqliteDb::run(&self.conn.borrow(), &s)
	}

	async fn batch(&self, s: Vec<Stmt>) -> Result<Vec<Exec>, DbError> {
		let conn = self.conn.borrow();
		let tx = conn.unchecked_transaction().map_err(e)?;
		let out = s.iter().map(|x| SqliteDb::run(&tx, x)).collect::<Result<Vec<_>, _>>()?;
		tx.commit().map_err(e)?;
		Ok(out)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use cfsa_core::db::{DbExt, RowExt, q};

	fn block<F: std::future::Future>(f: F) -> F::Output {
		tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
	}

	#[test]
	fn d1_semantics() {
		block(async {
			let db = SqliteDb::open(":memory:").unwrap();
			db.with(|c| c.execute_batch("CREATE TABLE t (k TEXT PRIMARY KEY, n INTEGER, x TEXT)").unwrap());
			assert_eq!(db.run(q("INSERT INTO t VALUES (?1, ?2, ?3)").b("a").b(1).b(None::<String>)).await.unwrap(), 1);
			let r = db.first(q("SELECT k, n, x FROM t WHERE k = ?").b("a")).await.unwrap().unwrap();
			assert_eq!((r.s("k"), r.i("n"), r.get("x").cloned()), ("a".into(), 1, Some(Value::Null)));
			assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"k":"a","n":1,"x":null}"#);
			assert_eq!(db.exec(q("SELECT * FROM t")).await.unwrap().changes, 0);
			// Upsert whose WHERE fails changes nothing.
			let n = db.run(q("INSERT INTO t VALUES ('a', 2, NULL) ON CONFLICT (k) DO UPDATE SET n = 2 WHERE 0")).await.unwrap();
			assert_eq!(n, 0);
			// A failing batch rolls back entirely.
			let r = db.batch(vec![q("INSERT INTO t VALUES ('b', 1, NULL)"), q("INSERT INTO t VALUES ('a', 1, NULL)")]).await;
			assert!(r.unwrap_err().is_unique());
			assert!(db.first(q("SELECT 1 FROM t WHERE k = 'b'")).await.unwrap().is_none());
		});
	}
}
