// Applies an app's migrations/*.sql in order, each in its own transaction, recording them in the same
// `d1_migrations` table cf/Wrangler use. Migrations are append-only, so a file is applied once by name.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { SqliteD1 } from "./d1.ts";

export function migrate(db: SqliteD1, dir: string, log: (msg: string) => void = () => {}): string[] {
	const s = db.sqlite;
	s.run(
		"CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
	);
	const applied = new Set((s.query("SELECT name FROM d1_migrations").all() as { name: string }[]).map((r) => r.name));
	const pending = readdirSync(dir)
		.filter((f) => f.endsWith(".sql") && !applied.has(f))
		.sort();
	for (const m of pending) {
		s.transaction(() => {
			s.run(readFileSync(join(dir, m), "utf8"));
			s.run("INSERT INTO d1_migrations (name) VALUES (?)", [m]);
		})();
		log(`applied migration ${m}`);
	}
	return pending;
}
