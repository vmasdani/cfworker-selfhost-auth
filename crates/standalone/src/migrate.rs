//! Applies an app's migrations in name order, each in its own transaction, recording them in the same
//! `d1_migrations` table cf/Wrangler and the Bun standalone server use. Migrations are append-only, so
//! a file is applied once by name. (Not `sqlx::migrate!`: its own table would re-run applied files.)

use crate::sqlite::SqliteDb;

pub fn migrate(db: &SqliteDb, migrations: &[(&str, &str)], log: &dyn Fn(&str)) -> Result<Vec<String>, String> {
	db.with(|c| {
		c.execute_batch(
			"CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
		)
		.map_err(|e| e.to_string())?;
		let applied: Vec<String> = {
			let mut st = c.prepare("SELECT name FROM d1_migrations").map_err(|e| e.to_string())?;
			st.query_map([], |r| r.get::<_, String>(0)).map_err(|e| e.to_string())?.filter_map(Result::ok).collect()
		};
		let mut pending: Vec<&(&str, &str)> = migrations.iter().filter(|(n, _)| !applied.iter().any(|a| a == n)).collect();
		pending.sort_by_key(|(n, _)| *n);
		let mut done = Vec::new();
		for (name, sql) in pending {
			let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
			tx.execute_batch(sql).map_err(|e| format!("{name}: {e}"))?;
			tx.execute("INSERT INTO d1_migrations (name) VALUES (?)", [name]).map_err(|e| e.to_string())?;
			tx.commit().map_err(|e| e.to_string())?;
			log(&format!("applied migration {name}"));
			done.push(name.to_string());
		}
		Ok(done)
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn applies_once_by_name() {
		let db = SqliteDb::open(":memory:").unwrap();
		let m = [("0002_b.sql", "ALTER TABLE a ADD COLUMN y INTEGER;"), ("0001_a.sql", "CREATE TABLE a (x INTEGER);")];
		assert_eq!(migrate(&db, &m, &|_| {}).unwrap(), vec!["0001_a.sql", "0002_b.sql"]);
		assert!(migrate(&db, &m, &|_| {}).unwrap().is_empty());
	}

	#[test]
	fn failed_migration_rolls_back() {
		let db = SqliteDb::open(":memory:").unwrap();
		let m = [("0001_a.sql", "CREATE TABLE a (x INTEGER); CREATE TABLE a (x INTEGER);")];
		assert!(migrate(&db, &m, &|_| {}).is_err());
		let n: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'a'", [], |r| r.get(0)).unwrap());
		assert_eq!(n, 0);
	}
}
