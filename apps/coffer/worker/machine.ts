// Machine REST API (/api/v1), used by the SDK snippets.
//
//   Authorization: Bearer <client id>.<base64 auth key>
//
// The auth key is HKDF(client secret, "coffer/v1/machine-auth"); the server stores HMAC(SERVER_SECRET,
// auth key). The client secret itself never leaves the client, and neither does the wrap key derived
// from it, which unwraps the environment key returned by GET /v1/identity.

import { assertNotLimited, hit, HttpError, type Limit } from "@cfsa/server-kit";
import { body, clientIp, type AppEnv, type Ctx } from "@cfsa/worker-accounts";
import type { Hono } from "hono";
import { MAC, param, parseJson } from "./common.ts";
import { deleteSecret, getSecret, listSecrets, putSecret, secretBody } from "./secrets.ts";

const AUTH = /^Bearer (cfi_[A-Za-z0-9_-]{22})\.([A-Za-z0-9+/]{43}=)$/;
const MIN = 60_000;
const TOUCH_EVERY_MS = 60 * MIN;

interface Identity {
	id: string;
	project_id: string;
	env_id: string;
	scope: "read" | "write";
	auth_verifier: string;
	wrapped_key: string;
	last_used_at: number | null;
	project: string;
	environment: string;
}

const limits = (c: Ctx, clientId: string): Limit[] => [
	{ key: `machine:id:${clientId}`, max: 30, windowMs: 15 * MIN },
	{ key: `machine:ip:${clientIp(c)}`, max: 60, windowMs: 15 * MIN },
];

async function machine(c: Ctx): Promise<Identity> {
	const m = AUTH.exec(c.req.header("Authorization") ?? "");
	if (!m) throw new HttpError(401, "unauthenticated", "Send Authorization: Bearer <client id>.<auth key>");
	const [, clientId, authKey] = m as unknown as [string, string, string];
	const l = limits(c, clientId);
	await assertNotLimited(c.env.DB, l);
	const row = await c.env.DB.prepare(
		`SELECT i.id, i.project_id, i.env_id, i.scope, i.auth_verifier, i.wrapped_key, i.last_used_at,
		        p.name AS project, e.name AS environment
		 FROM machine_identities i JOIN projects p ON p.id = i.project_id JOIN environments e ON e.id = i.env_id
		 WHERE i.id = ? AND i.revoked_at IS NULL`,
	).bind(clientId).first<Identity>();
	if (!row || !(await c.get("keys").verify(authKey, row.auth_verifier))) {
		await hit(c.env.DB, l);
		throw new HttpError(401, "invalid_credentials", "Unknown or revoked client ID, or wrong client secret");
	}
	const now = Date.now();
	if (!row.last_used_at || now - row.last_used_at > TOUCH_EVERY_MS) {
		c.executionCtx.waitUntil(c.env.DB.prepare("UPDATE machine_identities SET last_used_at = ? WHERE id = ?").bind(now, row.id).run());
	}
	return row;
}

function requireWrite(id: Identity) {
	if (id.scope !== "write") throw new HttpError(403, "read_only", "This client ID has read-only access");
}

export function machineRoutes(app: Hono<AppEnv>) {
	app.get("/v1/identity", async (c) => {
		const id = await machine(c);
		return c.json({
			clientId: id.id,
			scope: id.scope,
			projectId: id.project_id,
			project: id.project,
			envId: id.env_id,
			environment: id.environment,
			wrappedKey: parseJson(id.wrapped_key),
		});
	});

	app.get("/v1/secrets", async (c) => {
		const id = await machine(c);
		return c.json({ secrets: await listSecrets(c.env.DB, id.env_id) });
	});

	app.get("/v1/secrets/:mac", async (c) => {
		const id = await machine(c);
		const row = await getSecret(c.env.DB, id.env_id, param(c, "mac", MAC));
		if (!row) throw new HttpError(404, "secret_not_found");
		return c.json(row);
	});

	app.put("/v1/secrets/:mac", async (c) => {
		const id = await machine(c);
		requireWrite(id);
		const mac = param(c, "mac", MAC);
		return c.json(await putSecret(c.env.DB, id.env_id, mac, secretBody(await body(c)), `machine:${id.id}`));
	});

	app.delete("/v1/secrets/:mac", async (c) => {
		const id = await machine(c);
		requireWrite(id);
		return c.json({ deleted: await deleteSecret(c.env.DB, id.env_id, param(c, "mac", MAC), `machine:${id.id}`) });
	});
}
