// Fixed-window failure counters in D1 (table `rate_limits`). Low traffic, so one row per key is fine.

import { HttpError } from "./validate.ts";

export interface Limit {
	key: string;
	max: number;
	windowMs: number;
}

interface Row {
	count: number;
	window_start: number;
}

/** Throws 429 if any of the limits is exhausted. */
export async function assertNotLimited(db: D1Database, limits: Limit[], now = Date.now()): Promise<void> {
	for (const l of limits) {
		const row = await db.prepare("SELECT count, window_start FROM rate_limits WHERE key = ?").bind(l.key).first<Row>();
		if (row && now - row.window_start < l.windowMs && row.count >= l.max) {
			const retryAfter = Math.ceil((row.window_start + l.windowMs - now) / 1000);
			throw new HttpError(429, "rate_limited", "Too many attempts. Try again later.", { retryAfter });
		}
	}
}

/** Count one failure (or one use, for endpoints limited regardless of outcome). */
export async function hit(db: D1Database, limits: Limit[], now = Date.now()): Promise<void> {
	await db.batch(
		limits.map((l) =>
			db
				.prepare(
					`INSERT INTO rate_limits (key, count, window_start) VALUES (?1, 1, ?2)
					 ON CONFLICT(key) DO UPDATE SET
					   count = CASE WHEN ?2 - window_start >= ?3 THEN 1 ELSE count + 1 END,
					   window_start = CASE WHEN ?2 - window_start >= ?3 THEN ?2 ELSE window_start END`,
				)
				.bind(l.key, now, l.windowMs),
		),
	);
}

export async function clear(db: D1Database, keys: string[]): Promise<void> {
	if (keys.length) await db.batch(keys.map((k) => db.prepare("DELETE FROM rate_limits WHERE key = ?").bind(k)));
}
