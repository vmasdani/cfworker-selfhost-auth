// Encrypted entry sync. The server only ever sees ciphertext.
//
// Push: each change is accepted if it is newer than the stored one (client updatedAt, then revision):
// last-write-wins per entry, decided atomically in SQL. Accepted rows get the next per-user `seq`.
// Pull: rows with seq > cursor, oldest first.

import { bad, bool, b64, int, obj, str } from "@cfsa/server-kit";
import type { Hono } from "hono";
import { body, requireSession, type AppEnv } from "@cfsa/worker-accounts";

const MAX_CHANGES = 500;
const PAGE = 500;
const MAX_CT = 16_384;
const MAX_CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;
const ENTRY_ID = /^[A-Za-z0-9-]{1,64}$/;

interface Change {
	id: string;
	iv: string;
	ct: string;
	revision: number;
	updatedAt: number;
	deleted: boolean;
}

function parseChange(v: unknown): Change {
	const o = obj(v, "change");
	const id = str(o, "id", { max: 64 });
	if (!ENTRY_ID.test(id)) throw bad("invalid_request", "Invalid entry id");
	const deleted = bool(o, "deleted");
	return {
		id,
		deleted,
		iv: deleted ? "" : b64(o, "iv", { bytes: 12 }),
		ct: deleted ? "" : b64(o, "ct", { max: MAX_CT }),
		revision: int(o, "revision", { min: 1 }),
		// A client with a clock far in the future would otherwise win every conflict forever.
		updatedAt: int(o, "updatedAt", { min: 0, max: Date.now() + MAX_CLOCK_SKEW_MS }),
	};
}

export function syncRoutes(app: Hono<AppEnv>) {
	app.get("/sync", requireSession, async (c) => {
		const since = Number(c.req.query("since") ?? "0");
		if (!Number.isSafeInteger(since) || since < 0) throw bad("invalid_request", "Invalid cursor");
		const rows = await c.env.DB.prepare(
			`SELECT id, iv, ciphertext AS ct, revision, updated_at AS updatedAt, deleted, seq
			 FROM entries WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?`,
		).bind(c.get("user").id, since, PAGE).all<Omit<Change, "deleted"> & { seq: number; deleted: number }>();
		const entries = rows.results.map((r) => ({ ...r, deleted: r.deleted === 1 }));
		const cursor = entries.length ? entries[entries.length - 1]!.seq : since;
		return c.json({ entries, cursor, more: entries.length === PAGE });
	});

	app.post("/sync", requireSession, async (c) => {
		const b = await body(c);
		if (!Array.isArray(b.changes) || b.changes.length > MAX_CHANGES) throw bad("invalid_request", `changes: array of at most ${MAX_CHANGES}`);
		const changes = b.changes.map(parseChange);
		if (!changes.length) return c.json({ results: [] });
		const userId = c.get("user").id;
		const db = c.env.DB;
		const res = await db.batch(
			changes.map((ch) =>
				db.prepare(
					`INSERT INTO entries (user_id, id, ciphertext, iv, revision, updated_at, deleted, seq)
					 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, (SELECT COALESCE(MAX(seq), 0) + 1 FROM entries WHERE user_id = ?1))
					 ON CONFLICT (user_id, id) DO UPDATE SET
					   ciphertext = excluded.ciphertext, iv = excluded.iv, revision = excluded.revision,
					   updated_at = excluded.updated_at, deleted = excluded.deleted, seq = excluded.seq
					 WHERE excluded.updated_at > entries.updated_at
					    OR (excluded.updated_at = entries.updated_at AND excluded.revision > entries.revision)`,
				).bind(userId, ch.id, ch.ct, ch.iv, ch.revision, ch.updatedAt, ch.deleted ? 1 : 0),
			),
		);
		return c.json({
			results: changes.map((ch, i) => ({ id: ch.id, accepted: res[i]!.meta.changes === 1 })),
		});
	});
}
