import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrate, parseHeaders, SqliteD1, StaticSite } from "../src/index.ts";

function db() {
	const d = new SqliteD1(":memory:");
	d.sqlite.run("CREATE TABLE p (id TEXT PRIMARY KEY, n INTEGER NOT NULL)");
	d.sqlite.run("CREATE TABLE c (id TEXT PRIMARY KEY, p TEXT NOT NULL REFERENCES p (id) ON DELETE CASCADE)");
	return d;
}

describe("SqliteD1", () => {
	test("first, all, run with numbered parameters", async () => {
		const d = db();
		const r = await d.prepare("INSERT INTO p (id, n) VALUES (?1, ?2)").bind("a", 1).run();
		expect(r.meta.changes).toBe(1);
		expect(await d.prepare("SELECT n FROM p WHERE id = ?").bind("a").first<{ n: number }>()).toEqual({ n: 1 });
		expect(await d.prepare("SELECT n FROM p WHERE id = ?").bind("a").first<number>("n")).toBe(1);
		expect(await d.prepare("SELECT n FROM p WHERE id = ?").bind("zz").first()).toBeNull();
		expect((await d.prepare("SELECT id FROM p").all()).results).toEqual([{ id: "a" }]);
		expect(await d.prepare("SELECT id, n FROM p").raw()).toEqual([["a", 1]]);
	});

	test("conditional upsert reports 0 changes when the WHERE rejects it", async () => {
		const d = db();
		const up = "INSERT INTO p (id, n) VALUES (?1, ?2) ON CONFLICT (id) DO UPDATE SET n = excluded.n WHERE excluded.n > p.n";
		await d.prepare(up).bind("a", 5).run();
		expect((await d.prepare(up).bind("a", 3).run()).meta.changes).toBe(0);
		expect((await d.prepare(up).bind("a", 9).run()).meta.changes).toBe(1);
	});

	test("SELECT after a write reports 0 changes", async () => {
		const d = db();
		await d.prepare("INSERT INTO p VALUES ('a', 1)").run();
		const [, sel] = await d.batch([d.prepare("INSERT INTO p VALUES ('b', 2)"), d.prepare("SELECT * FROM p")]);
		expect(sel!.meta.changes).toBe(0);
		expect(sel!.results).toHaveLength(2);
	});

	test("RETURNING returns rows and counts changes", async () => {
		const d = db();
		const r = await d.prepare("INSERT INTO p VALUES ('a', 1), ('b', 2) RETURNING id").all();
		expect(r.results).toEqual([{ id: "a" }, { id: "b" }]);
		expect(r.meta.changes).toBe(2);
	});

	test("batch is atomic", async () => {
		const d = db();
		await expect(
			d.batch([d.prepare("INSERT INTO p VALUES ('a', 1)"), d.prepare("INSERT INTO p VALUES ('a', 2)")]),
		).rejects.toThrow();
		expect(await d.prepare("SELECT COUNT(*) AS n FROM p").first<number>("n")).toBe(0);
	});

	test("foreign keys are enforced and cascade", async () => {
		const d = db();
		await expect(d.prepare("INSERT INTO c VALUES ('x', 'missing')").run()).rejects.toThrow();
		await d.batch([d.prepare("INSERT INTO p VALUES ('a', 1)"), d.prepare("INSERT INTO c VALUES ('x', 'a')")]);
		await d.prepare("DELETE FROM p").run();
		expect(await d.prepare("SELECT COUNT(*) AS n FROM c").first<number>("n")).toBe(0);
	});

	test("rejects undefined, converts booleans", async () => {
		const d = db();
		expect(() => d.prepare("SELECT ?").bind(undefined as never)).toThrow(/undefined/);
		expect(await d.prepare("SELECT ? AS v").bind(true).first<number>("v")).toBe(1);
	});
});

describe("migrate", () => {
	test("applies each file once, in order", () => {
		const dir = mkdtempSync(join(tmpdir(), "cfsa-mig-"));
		try {
			writeFileSync(join(dir, "0002_b.sql"), "ALTER TABLE t ADD COLUMN b INTEGER;");
			writeFileSync(join(dir, "0001_a.sql"), "CREATE TABLE t (a INTEGER); CREATE INDEX t_a ON t (a);");
			const d = new SqliteD1(":memory:");
			expect(migrate(d, dir)).toEqual(["0001_a.sql", "0002_b.sql"]);
			expect(migrate(d, dir)).toEqual([]);
			d.sqlite.run("INSERT INTO t (a, b) VALUES (1, 2)");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});
});

describe("StaticSite", () => {
	test("_headers, SPA fallback, ETag, compression", async () => {
		const dir = mkdtempSync(join(tmpdir(), "cfsa-static-"));
		try {
			writeFileSync(join(dir, "index.html"), "<!doctype html>" + "x".repeat(2000));
			writeFileSync(join(dir, "sw.js"), "self");
			writeFileSync(join(dir, "_headers"), "/*\n  X-Test: all\n/sw.js\n  Cache-Control: no-cache\n");
			const site = new StaticSite(dir);
			const get = (p: string, h: Record<string, string> = {}) => site.respond(new Request(`http://x${p}`, { headers: h }), p);

			const home = get("/", { "Accept-Encoding": "gzip, br" })!;
			expect(home.headers.get("X-Test")).toBe("all");
			expect(home.headers.get("Content-Encoding")).toBe("br");
			expect(get("/settings/sync")!.headers.get("Content-Type")).toStartWith("text/html");
			expect(get("/missing.js")).toBeNull();
			expect(await get("/_headers")!.text()).toStartWith("<!doctype html>");
			expect(get("/sw.js")!.headers.get("Cache-Control")).toBe("no-cache");
			expect(get("/", { "If-None-Match": home.headers.get("ETag")! })!.status).toBe(304);
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	});

	test("parseHeaders patterns", () => {
		const [r] = parseHeaders("/assets/:file.js\n  A: b");
		expect(r!.pattern.test("/assets/x.js")).toBe(true);
		expect(r!.pattern.test("/assets/a/x.js")).toBe(false);
	});
});
