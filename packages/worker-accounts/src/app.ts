import { HttpError, findSession, readSessionCookie, serverKeys, type ServerKeys, type SessionRow } from "@cfsa/server-kit";
import { Hono, type Context } from "hono";
import { userById, type UserRow } from "./db.ts";

export interface AccountsConfig {
	/** Shown in the login TOTP issuer, e.g. "Tumbler (host)". */
	appName: string;
	/** Session cookie name; must start with __Host-. */
	cookie: string;
	/** AAD namespace for the server-sealed login TOTP secret, e.g. "tumbler". Never change it once deployed. */
	aadPrefix: string;
}

/** Bindings every app with accounts has. */
export interface AccountsBindings {
	DB: D1Database;
	SERVER_SECRET: string;
	ADMIN_SETUP_TOKEN: string;
}

export type Vars = { user: UserRow; session: SessionRow; keys: ServerKeys; cfg: AccountsConfig };
export type AppEnv = { Bindings: AccountsBindings; Variables: Vars };
export type Ctx = Context<AppEnv>;

export function createApp(cfg: AccountsConfig) {
	if (!cfg.cookie.startsWith("__Host-")) throw new Error("Session cookie name must start with __Host-");
	const app = new Hono<AppEnv>().basePath("/api");

	app.use("*", async (c, next) => {
		c.set("cfg", cfg);
		// CSRF: state-changing requests must be same-origin JSON. Browsers send Origin on cross-site
		// requests, and a cross-site form cannot send application/json without a CORS preflight.
		if (c.req.method !== "GET" && c.req.method !== "HEAD") {
			const origin = c.req.header("Origin");
			if (origin && origin !== new URL(c.req.url).origin) throw new HttpError(403, "forbidden_origin");
			if (c.req.method !== "DELETE" && !c.req.header("Content-Type")?.startsWith("application/json")) {
				throw new HttpError(415, "json_required");
			}
		}
		c.set("keys", await serverKeys(c.env.SERVER_SECRET));
		await next();
		c.header("Cache-Control", "no-store");
	});

	app.onError((err, c) => {
		if (err instanceof HttpError) {
			if (err.status === 429 && typeof err.extra?.retryAfter === "number") c.header("Retry-After", String(err.extra.retryAfter));
			return c.json({ error: err.code, message: err.message, ...err.extra }, err.status as 400);
		}
		console.error(err);
		return c.json({ error: "internal_error" }, 500);
	});

	return app;
}

/** Middleware: require a valid session; sets `user` and `session`. */
export async function requireSession(c: Ctx, next: () => Promise<void>) {
	const token = readSessionCookie(c.req.header("Cookie"), c.get("cfg").cookie);
	const session = token ? await findSession(c.env.DB, token) : null;
	if (!session) throw new HttpError(401, "unauthenticated");
	const user = await userById(c.env.DB, session.user_id);
	if (!user || user.disabled) throw new HttpError(401, "unauthenticated");
	c.set("session", session);
	c.set("user", user);
	await next();
}

export async function requireAdmin(c: Ctx, next: () => Promise<void>) {
	if (c.get("user").role !== "admin") throw new HttpError(403, "admin_only");
	await next();
}

export async function body(c: Ctx): Promise<Record<string, unknown>> {
	try {
		const v = await c.req.json();
		if (typeof v === "object" && v && !Array.isArray(v)) return v as Record<string, unknown>;
	} catch {
		// fall through
	}
	throw new HttpError(400, "invalid_json");
}

export const clientIp = (c: Ctx) => c.req.header("CF-Connecting-IP") ?? "local";

export async function audit(c: Ctx, userId: string | null, event: string, meta?: Record<string, unknown>) {
	await c.env.DB.prepare("INSERT INTO audit_log (user_id, event, at, meta) VALUES (?, ?, ?, ?)")
		.bind(userId, event, Date.now(), meta ? JSON.stringify(meta) : null)
		.run();
}
