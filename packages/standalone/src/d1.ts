// The subset of the D1 API the apps use (prepare/bind/first/all/run/raw, batch, exec), backed by a
// local SQLite file through bun:sqlite. Lets the unchanged Worker code run on a plain server.
//
// Semantics kept from D1: `?NNN` and `?` parameters, foreign keys enforced, `batch` is one
// transaction (all statements or none), `first()` returns null for no row, `meta.changes` counts the
// rows the statement changed, undefined bind values are rejected.

import { Database, type SQLQueryBindings, type Statement } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

type Value = string | number | bigint | boolean | null | ArrayBuffer | ArrayBufferView;

export interface D1Meta {
	duration: number;
	changes: number;
	last_row_id: number;
	changed_db: boolean;
	rows_read: number;
	rows_written: number;
	size_after: number;
}

export interface D1Result<T = Record<string, unknown>> {
	success: true;
	results: T[];
	meta: D1Meta;
}

function toBinding(v: Value, i: number): SQLQueryBindings {
	if (v === undefined) throw new TypeError(`D1_TYPE_ERROR: Type 'undefined' not supported for value at index ${i}`);
	if (typeof v === "boolean") return v ? 1 : 0;
	if (v instanceof ArrayBuffer) return new Uint8Array(v);
	return v as SQLQueryBindings;
}

export class SqliteD1Statement {
	constructor(
		private readonly db: SqliteD1,
		private readonly sql: string,
		private readonly params: SQLQueryBindings[] = [],
	) {}

	bind(...values: Value[]): SqliteD1Statement {
		return new SqliteD1Statement(this.db, this.sql, values.map(toBinding));
	}

	private stmt(): Statement {
		return this.db.sqlite.query(this.sql);
	}

	async first<T = Record<string, unknown>>(column?: string): Promise<T | null> {
		const row = (this.stmt().get(...this.params) as Record<string, unknown> | null) ?? null;
		if (row === null) return null;
		if (column === undefined) return row as T;
		if (!(column in row)) throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${column})`);
		return row[column] as T;
	}

	async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		return this.execute() as D1Result<T>;
	}

	async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		return this.execute() as D1Result<T>;
	}

	async raw<T = unknown[]>(opts?: { columnNames?: boolean }): Promise<T[]> {
		const s = this.stmt();
		const rows = s.values(...this.params) as T[];
		return opts?.columnNames ? [s.columnNames as T, ...rows] : rows;
	}

	/** Synchronous execution, so `batch` can run inside one bun:sqlite transaction. */
	execute(): D1Result {
		const start = performance.now();
		const s = this.stmt();
		let results: Record<string, unknown>[] = [];
		let changes = 0;
		let lastRowId = 0;
		if (s.columnNames.length > 0) {
			// SELECT, or a write with RETURNING.
			results = s.all(...this.params) as Record<string, unknown>[];
			const c = this.db.sqlite.query("SELECT changes() AS c, last_insert_rowid() AS r").get() as { c: number; r: number };
			changes = /^\s*(?:WITH\b[\s\S]*?\)\s*)?SELECT\b/i.test(this.sql) ? 0 : c.c;
			lastRowId = c.r;
		} else {
			const r = s.run(...this.params);
			changes = r.changes;
			lastRowId = Number(r.lastInsertRowid);
		}
		return {
			success: true,
			results,
			meta: {
				duration: performance.now() - start,
				changes,
				last_row_id: lastRowId,
				changed_db: changes > 0,
				rows_read: results.length,
				rows_written: changes,
				size_after: 0,
			},
		};
	}
}

export class SqliteD1 {
	readonly sqlite: Database;

	constructor(path: string) {
		if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
		this.sqlite = new Database(path, { create: true, strict: false });
		// WAL: readers never block the writer; NORMAL is durable across process crashes in WAL mode.
		this.sqlite.run("PRAGMA journal_mode = WAL");
		this.sqlite.run("PRAGMA synchronous = NORMAL");
		this.sqlite.run("PRAGMA busy_timeout = 5000");
		this.sqlite.run("PRAGMA foreign_keys = ON");
	}

	prepare(sql: string): SqliteD1Statement {
		return new SqliteD1Statement(this, sql);
	}

	async batch<T = Record<string, unknown>>(statements: SqliteD1Statement[]): Promise<D1Result<T>[]> {
		return this.sqlite.transaction(() => statements.map((s) => s.execute()))() as D1Result<T>[];
	}

	async exec(sql: string): Promise<{ count: number; duration: number }> {
		const start = performance.now();
		this.sqlite.run(sql);
		return { count: sql.split(";").filter((s) => s.trim()).length, duration: performance.now() - start };
	}

	close() {
		try {
			this.sqlite.run("PRAGMA optimize");
		} finally {
			this.sqlite.close();
		}
	}
}
