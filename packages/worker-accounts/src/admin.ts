// Admin: single-use invite links. The token is shown once; only its hash is stored.

import { randomBytes, toB64Url } from "@cfsa/crypto";
import { HttpError, int, obj, str } from "@cfsa/server-kit";
import type { Hono } from "hono";
import { audit, body, requireAdmin, requireSession, type AppEnv } from "./app.ts";
import { inviteHash } from "./auth.ts";

const HOUR = 3_600_000;

export function adminRoutes(app: Hono<AppEnv>) {
	app.use("/admin/*", requireSession, requireAdmin);

	app.post("/admin/invites", async (c) => {
		const b = obj(await body(c));
		const role = b.role === undefined ? "user" : str(b, "role", { max: 8 });
		if (role !== "user" && role !== "admin") throw new HttpError(400, "invalid_role");
		const hours = b.ttlHours === undefined ? 24 : int(b, "ttlHours", { min: 1, max: 24 * 14 });
		const token = toB64Url(randomBytes(32));
		const id = crypto.randomUUID();
		const now = Date.now();
		await c.env.DB.prepare(
			"INSERT INTO invites (id, token_hash, role, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		).bind(id, await inviteHash(token), role, c.get("user").id, now, now + hours * HOUR).run();
		await audit(c, c.get("user").id, "invite_create", { inviteId: id, role });
		return c.json({ id, token, role, expiresAt: now + hours * HOUR });
	});

	app.get("/admin/invites", async (c) => {
		const rows = await c.env.DB.prepare(
			`SELECT i.id, i.role, i.created_at AS createdAt, i.expires_at AS expiresAt, i.used_at AS usedAt, u.username AS usedBy
			 FROM invites i LEFT JOIN users u ON u.id = i.used_by ORDER BY i.created_at DESC LIMIT 100`,
		).all();
		return c.json({ invites: rows.results });
	});

	app.delete("/admin/invites/:id", async (c) => {
		await c.env.DB.prepare("DELETE FROM invites WHERE id = ? AND used_at IS NULL").bind(c.req.param("id")).run();
		return c.json({ ok: true });
	});

	app.get("/admin/users", async (c) => {
		const rows = await c.env.DB.prepare(
			`SELECT id, username, role, disabled, login_totp_enabled AS totpEnabled, created_at AS createdAt
			 FROM users ORDER BY created_at`,
		).all();
		return c.json({ users: rows.results });
	});
}
