// Dashboard API (session cookie): user key pairs, projects, environments, members, secrets and
// machine identities. Every key the server stores here is wrapped client-side.

import { b64, bad, HttpError, obj, str, username as usernameField } from "@cfsa/server-kit";
import { audit, body, requireSession, type AppEnv, type Ctx } from "@cfsa/worker-accounts";
import type { Hono } from "hono";
import {
	CLIENT_ID,
	MAC,
	envMembership,
	envName,
	memberWrap,
	membership,
	param,
	parseJson,
	projectName,
	role,
	sealedKey,
	uuid,
} from "./common.ts";
import { deleteSecret, getSecret, listSecrets, putSecret, secretBody, secretHistory } from "./secrets.ts";

const MAX_ENVS = 20;
const MAX_PROJECTS_PER_USER = 200;

const userTag = (c: Ctx) => `user:${c.get("user").id}`;

export function projectRoutes(app: Hono<AppEnv>) {
	for (const p of ["/keys", "/users/*", "/projects", "/projects/*", "/environments/*", "/identities/*"]) app.use(p, requireSession);

	// --- the user's own ECDH key pair --------------------------------------------------------------

	app.get("/keys", async (c) => {
		const row = await c.env.DB.prepare("SELECT public_key, wrapped_private_key FROM user_keys WHERE user_id = ?")
			.bind(c.get("user").id)
			.first<{ public_key: string; wrapped_private_key: string }>();
		return c.json(row ? { publicKey: row.public_key, wrappedPrivateKey: parseJson(row.wrapped_private_key) } : { publicKey: null });
	});

	// Set once. The vault key never changes (password change and recovery re-wrap it), so neither does this.
	app.put("/keys", async (c) => {
		const b = await body(c);
		const publicKey = b64(b, "publicKey", { max: 256 });
		const wrapped = sealedKey(b, "wrappedPrivateKey");
		const r = await c.env.DB.prepare(
			"INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (user_id) DO NOTHING",
		).bind(c.get("user").id, publicKey, JSON.stringify(wrapped), Date.now()).run();
		if (r.meta.changes !== 1) throw new HttpError(409, "keys_exist", "This account already has a key pair");
		await audit(c, c.get("user").id, "keys_create");
		return c.json({ ok: true });
	});

	app.get("/users/:username/key", async (c) => {
		const u = usernameField({ username: c.req.param("username") });
		const row = await c.env.DB.prepare(
			`SELECT u.id, u.username, k.public_key AS publicKey FROM users u LEFT JOIN user_keys k ON k.user_id = u.id
			 WHERE u.username = ? AND u.disabled = 0`,
		).bind(u).first<{ id: string; username: string; publicKey: string | null }>();
		if (!row) throw new HttpError(404, "user_not_found", "No such user");
		if (!row.publicKey) throw new HttpError(409, "user_has_no_keys", "That user has not signed in to Coffer yet");
		return c.json({ userId: row.id, username: row.username, publicKey: row.publicKey });
	});

	// --- projects ----------------------------------------------------------------------------------

	// Everything the dashboard needs after unlock, in one request.
	app.get("/projects", async (c) => {
		const userId = c.get("user").id;
		const [projects, envs] = await c.env.DB.batch([
			c.env.DB.prepare(
				`SELECT p.id, p.name, p.created_at AS createdAt, m.role, m.wrapped_key AS wrappedKey
				 FROM projects p JOIN project_members m ON m.project_id = p.id AND m.user_id = ? ORDER BY p.name COLLATE NOCASE`,
			).bind(userId),
			c.env.DB.prepare(
				`SELECT e.id, e.project_id AS projectId, e.name, e.position, e.wrapped_key AS wrappedKey,
				        (SELECT COUNT(*) FROM secrets s WHERE s.env_id = e.id) AS secretCount
				 FROM environments e JOIN project_members m ON m.project_id = e.project_id AND m.user_id = ?
				 ORDER BY e.position, e.created_at`,
			).bind(userId),
		]);
		type P = { id: string; name: string; createdAt: number; role: string; wrappedKey: string };
		type E = { id: string; projectId: string; name: string; position: number; wrappedKey: string; secretCount: number };
		const byProject = new Map<string, unknown[]>();
		for (const e of envs!.results as E[]) {
			const list = byProject.get(e.projectId) ?? [];
			list.push({ id: e.id, name: e.name, position: e.position, secretCount: e.secretCount, wrappedKey: parseJson(e.wrappedKey) });
			byProject.set(e.projectId, list);
		}
		return c.json({
			projects: (projects!.results as P[]).map((p) => ({
				...p,
				wrappedKey: parseJson(p.wrappedKey),
				environments: byProject.get(p.id) ?? [],
			})),
		});
	});

	// IDs are client-generated: they are bound into the ciphertext (AAD) before the server sees them.
	app.post("/projects", async (c) => {
		const b = await body(c);
		const id = uuid(b, "id");
		const name = projectName(b);
		const wrappedKey = memberWrap(b);
		if (!Array.isArray(b.environments) || b.environments.length < 1 || b.environments.length > MAX_ENVS) {
			throw bad("invalid_request", `environments: 1–${MAX_ENVS} items`);
		}
		const envs = b.environments.map((v) => {
			const o = obj(v, "environment");
			return { id: uuid(o, "id"), name: envName(o), wrappedKey: sealedKey(o, "wrappedKey") };
		});
		if (new Set(envs.map((e) => e.name.toLowerCase())).size !== envs.length) throw bad("duplicate_environment");
		const userId = c.get("user").id;
		const count = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM project_members WHERE user_id = ?").bind(userId).first<{ n: number }>();
		if ((count?.n ?? 0) >= MAX_PROJECTS_PER_USER) throw bad("too_many_projects");
		const now = Date.now();
		try {
			await c.env.DB.batch([
				c.env.DB.prepare("INSERT INTO projects (id, name, created_by, created_at) VALUES (?, ?, ?, ?)").bind(id, name, userId, now),
				c.env.DB.prepare(
					"INSERT INTO project_members (project_id, user_id, role, wrapped_key, added_by, created_at) VALUES (?, ?, 'owner', ?, ?, ?)",
				).bind(id, userId, JSON.stringify(wrappedKey), userId, now),
				...envs.map((e, i) =>
					c.env.DB.prepare("INSERT INTO environments (id, project_id, name, position, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?)")
						.bind(e.id, id, e.name, i, JSON.stringify(e.wrappedKey), now),
				),
			]);
		} catch (e) {
			if (String(e).includes("UNIQUE")) throw new HttpError(409, "id_conflict");
			throw e;
		}
		await audit(c, userId, "project_create", { projectId: id });
		return c.json({ ok: true });
	});

	app.patch("/projects/:pid", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid, "owner");
		const name = projectName(await body(c));
		await c.env.DB.prepare("UPDATE projects SET name = ? WHERE id = ?").bind(name, pid).run();
		return c.json({ ok: true });
	});

	app.delete("/projects/:pid", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid, "owner");
		await c.env.DB.prepare("DELETE FROM projects WHERE id = ?").bind(pid).run();
		await audit(c, c.get("user").id, "project_delete", { projectId: pid });
		return c.json({ ok: true });
	});

	// --- environments --------------------------------------------------------------------------------

	app.post("/projects/:pid/environments", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid, "owner");
		const b = await body(c);
		const id = uuid(b, "id");
		const name = envName(b);
		const wrappedKey = sealedKey(b, "wrappedKey");
		const n = await c.env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(MAX(position), -1) AS max FROM environments WHERE project_id = ?")
			.bind(pid).first<{ n: number; max: number }>();
		if ((n?.n ?? 0) >= MAX_ENVS) throw bad("too_many_environments");
		try {
			await c.env.DB.prepare("INSERT INTO environments (id, project_id, name, position, wrapped_key, created_at) VALUES (?, ?, ?, ?, ?, ?)")
				.bind(id, pid, name, (n?.max ?? -1) + 1, JSON.stringify(wrappedKey), Date.now()).run();
		} catch (e) {
			if (String(e).includes("UNIQUE")) throw new HttpError(409, "environment_exists", "An environment with that name exists");
			throw e;
		}
		await audit(c, c.get("user").id, "environment_create", { projectId: pid, envId: id });
		return c.json({ ok: true });
	});

	app.patch("/environments/:eid", async (c) => {
		const eid = param(c, "eid");
		const m = await envMembership(c, eid);
		if (m.role !== "owner") throw new HttpError(403, "owner_only");
		const name = envName(await body(c));
		try {
			await c.env.DB.prepare("UPDATE environments SET name = ? WHERE id = ?").bind(name, eid).run();
		} catch (e) {
			if (String(e).includes("UNIQUE")) throw new HttpError(409, "environment_exists", "An environment with that name exists");
			throw e;
		}
		return c.json({ ok: true });
	});

	app.delete("/environments/:eid", async (c) => {
		const eid = param(c, "eid");
		const m = await envMembership(c, eid);
		if (m.role !== "owner") throw new HttpError(403, "owner_only");
		const n = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM environments WHERE project_id = ?").bind(m.projectId).first<{ n: number }>();
		if ((n?.n ?? 0) <= 1) throw bad("last_environment", "A project needs at least one environment");
		await c.env.DB.prepare("DELETE FROM environments WHERE id = ?").bind(eid).run();
		await audit(c, c.get("user").id, "environment_delete", { projectId: m.projectId, envId: eid });
		return c.json({ ok: true });
	});

	// --- members -----------------------------------------------------------------------------------

	app.get("/projects/:pid/members", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid);
		const r = await c.env.DB.prepare(
			`SELECT u.id AS userId, u.username, m.role, m.created_at AS addedAt FROM project_members m
			 JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY m.created_at`,
		).bind(pid).all();
		return c.json({ members: r.results });
	});

	// The owner fetched the user's public key and wrapped the project key to it.
	app.post("/projects/:pid/members", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid, "owner");
		const b = await body(c);
		const userId = uuid(b, "userId");
		const r = role(b);
		const wrappedKey = memberWrap(b);
		const target = await c.env.DB.prepare(
			"SELECT u.id FROM users u JOIN user_keys k ON k.user_id = u.id WHERE u.id = ? AND u.disabled = 0",
		).bind(userId).first();
		if (!target) throw new HttpError(404, "user_not_found");
		const ins = await c.env.DB.prepare(
			`INSERT INTO project_members (project_id, user_id, role, wrapped_key, added_by, created_at) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (project_id, user_id) DO NOTHING`,
		).bind(pid, userId, r, JSON.stringify(wrappedKey), c.get("user").id, Date.now()).run();
		if (ins.meta.changes !== 1) throw new HttpError(409, "already_member", "That user is already a member");
		await audit(c, c.get("user").id, "member_add", { projectId: pid, userId, role: r });
		return c.json({ ok: true });
	});

	app.patch("/projects/:pid/members/:uid", async (c) => {
		const pid = param(c, "pid");
		const uid = param(c, "uid");
		await membership(c, pid, "owner");
		const r = role(await body(c));
		if (r === "member") await assertAnotherOwner(c, pid, uid);
		await c.env.DB.prepare("UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?").bind(r, pid, uid).run();
		return c.json({ ok: true });
	});

	// Owners can remove anyone; members can remove themselves. Removal does not rotate keys: a removed
	// member who kept a copy of the project key could still decrypt ciphertext obtained some other way.
	app.delete("/projects/:pid/members/:uid", async (c) => {
		const pid = param(c, "pid");
		const uid = param(c, "uid");
		const self = uid === c.get("user").id;
		await membership(c, pid, self ? undefined : "owner");
		await assertAnotherOwner(c, pid, uid);
		await c.env.DB.prepare("DELETE FROM project_members WHERE project_id = ? AND user_id = ?").bind(pid, uid).run();
		await audit(c, c.get("user").id, "member_remove", { projectId: pid, userId: uid });
		return c.json({ ok: true });
	});

	// --- secrets -------------------------------------------------------------------------------------

	app.get("/environments/:eid/secrets", async (c) => {
		const eid = param(c, "eid");
		await envMembership(c, eid);
		return c.json({ secrets: await listSecrets(c.env.DB, eid) });
	});

	app.put("/environments/:eid/secrets/:mac", async (c) => {
		const eid = param(c, "eid");
		const mac = param(c, "mac", MAC);
		await envMembership(c, eid);
		const row = await putSecret(c.env.DB, eid, mac, secretBody(await body(c)), userTag(c));
		return c.json(row);
	});

	app.delete("/environments/:eid/secrets/:mac", async (c) => {
		const eid = param(c, "eid");
		const mac = param(c, "mac", MAC);
		await envMembership(c, eid);
		return c.json({ deleted: await deleteSecret(c.env.DB, eid, mac, userTag(c)) });
	});

	app.get("/environments/:eid/secrets/:mac", async (c) => {
		const eid = param(c, "eid");
		const mac = param(c, "mac", MAC);
		await envMembership(c, eid);
		const row = await getSecret(c.env.DB, eid, mac);
		if (!row) throw new HttpError(404, "secret_not_found");
		return c.json(row);
	});

	app.get("/environments/:eid/secrets/:mac/history", async (c) => {
		const eid = param(c, "eid");
		const mac = param(c, "mac", MAC);
		await envMembership(c, eid);
		return c.json({ history: await secretHistory(c.env.DB, eid, mac) });
	});

	// --- machine identities --------------------------------------------------------------------------

	app.get("/projects/:pid/identities", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid);
		const r = await c.env.DB.prepare(
			`SELECT i.id, i.env_id AS envId, i.name, i.scope, i.created_at AS createdAt, i.last_used_at AS lastUsedAt,
			        u.username AS createdBy
			 FROM machine_identities i LEFT JOIN users u ON u.id = i.created_by
			 WHERE i.project_id = ? AND i.revoked_at IS NULL ORDER BY i.created_at DESC`,
		).bind(pid).all();
		return c.json({ identities: r.results });
	});

	// The browser generated the client secret; the server receives only the derived auth key (stored as
	// an HMAC) and the environment key wrapped by the secret's wrap key.
	app.post("/projects/:pid/identities", async (c) => {
		const pid = param(c, "pid");
		await membership(c, pid, "owner");
		const b = await body(c);
		const id = str(b, "id", { max: 26 });
		if (!CLIENT_ID.test(id)) throw bad("invalid_request", "Invalid client ID");
		const envId = uuid(b, "envId");
		const name = projectName(b);
		const scope = str(b, "scope", { max: 5 });
		if (scope !== "read" && scope !== "write") throw bad("invalid_scope");
		const authKey = b64(b, "authKey", { bytes: 32 });
		const wrappedKey = sealedKey(b, "wrappedKey");
		const env = await c.env.DB.prepare("SELECT 1 FROM environments WHERE id = ? AND project_id = ?").bind(envId, pid).first();
		if (!env) throw new HttpError(404, "environment_not_found");
		try {
			await c.env.DB.prepare(
				`INSERT INTO machine_identities (id, project_id, env_id, name, scope, auth_verifier, wrapped_key, created_by, created_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			).bind(id, pid, envId, name, scope, await c.get("keys").verifier(authKey), JSON.stringify(wrappedKey), c.get("user").id, Date.now()).run();
		} catch (e) {
			if (String(e).includes("UNIQUE")) throw new HttpError(409, "id_conflict");
			throw e;
		}
		await audit(c, c.get("user").id, "identity_create", { projectId: pid, envId, clientId: id, scope });
		return c.json({ ok: true });
	});

	app.delete("/identities/:id", async (c) => {
		const id = param(c, "id", CLIENT_ID);
		const row = await c.env.DB.prepare("SELECT project_id AS projectId FROM machine_identities WHERE id = ? AND revoked_at IS NULL")
			.bind(id).first<{ projectId: string }>();
		if (!row) throw new HttpError(404, "not_found");
		await membership(c, row.projectId, "owner");
		await c.env.DB.prepare("UPDATE machine_identities SET revoked_at = ? WHERE id = ?").bind(Date.now(), id).run();
		await audit(c, c.get("user").id, "identity_revoke", { projectId: row.projectId, clientId: id });
		return c.json({ ok: true });
	});
}

async function assertAnotherOwner(c: Ctx, projectId: string, leavingUserId: string) {
	const r = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM project_members WHERE project_id = ? AND role = 'owner' AND user_id != ?")
		.bind(projectId, leavingUserId).first<{ n: number }>();
	if ((r?.n ?? 0) < 1) throw bad("last_owner", "A project needs at least one owner");
}
