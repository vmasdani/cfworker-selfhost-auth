// Apply D1 migrations to the LOCAL dev database (the Cloudflare Vite plugin keeps it under
// .cloudflare/state). Dev-only helper: `cf d1 migrations apply --local` needs a database ID, which a
// binding without an ID does not have locally. Production uses `cf d1 migrations apply <DATABASE_ID>`.
//
// The local database file exists only after the dev/preview server first touched the DB binding
// (any /api request that queries D1). Uses the same `d1_migrations` table as cf/Wrangler.

import { Database } from "bun:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const dir = join(root, ".cloudflare/state/v3/d1/miniflare-D1DatabaseObject");
let files: string[];
try {
	files = readdirSync(dir).filter((f) => f.endsWith(".sqlite") && f !== "metadata.sqlite");
} catch {
	files = [];
}
if (files.length !== 1) {
	console.error(`Expected exactly one local D1 database in ${dir}, found ${files.length}. Start the dev server and hit /api/setup first.`);
	process.exit(1);
}

const db = new Database(join(dir, files[0]!));
db.run(
	"CREATE TABLE IF NOT EXISTS d1_migrations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
);
const applied = new Set(db.query("SELECT name FROM d1_migrations").all().map((r) => (r as { name: string }).name));
const migrations = readdirSync(join(root, "migrations")).filter((f) => f.endsWith(".sql")).sort();
for (const m of migrations) {
	if (applied.has(m)) continue;
	db.transaction(() => {
		db.run(readFileSync(join(root, "migrations", m), "utf8"));
		db.run("INSERT INTO d1_migrations (name) VALUES (?)", [m]);
	})();
	console.log(`applied ${m}`);
}
console.log("local database up to date");
