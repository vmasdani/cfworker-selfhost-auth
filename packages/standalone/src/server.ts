// Standalone mode: run an app's unchanged Worker (Hono) code on Bun with a local SQLite file instead of
// D1, and serve its built web app. Meant for one process per app under pm2 (fork mode) or systemd,
// behind a TLS reverse proxy (Caddy, nginx, Cloudflare Tunnel).
//
// Configuration (environment; Bun also loads .env from the working directory):
//   PORT              listen port (default: the app's)
//   HOST              listen address (default 127.0.0.1: only the reverse proxy can connect)
//   DATA_DIR          database and generated secrets (default ./data)
//   DATABASE_PATH     SQLite file (default $DATA_DIR/<app>.sqlite)
//   PUBLIC_URL        public origin, e.g. https://tumbler.example.com. Used for the same-origin (CSRF)
//                     check and the login TOTP issuer. Strongly recommended behind a proxy.
//   TRUST_PROXY       1/0: take the client IP (rate limits) and, without PUBLIC_URL, the origin from
//                     X-Forwarded-* headers. Default: 1 when HOST is a loopback address, else 0.
//   CLIENT_IP_HEADER  header holding the client IP instead of X-Forwarded-For, e.g. CF-Connecting-IP
//                     behind Cloudflare Tunnel. Only read when TRUST_PROXY is on.
//   SERVER_SECRET     default: generated once into $DATA_DIR/server-secret (0600). Never change it.
//   ADMIN_SETUP_TOKEN default: while there are no users, a fresh one is written on every start to
//                     $DATA_DIR/admin-setup-token (0600) and removed once the first admin exists.

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { SqliteD1 } from "./d1.ts";
import { migrate } from "./migrate.ts";
import { StaticSite } from "./static.ts";

interface ExecutionContext {
	waitUntil(p: Promise<unknown>): void;
	passThroughOnException(): void;
	props: Record<string, unknown>;
}

export interface FetchApp {
	fetch(req: Request, env: never, ctx: never): Response | Promise<Response>;
}

export interface StandaloneOptions {
	/** Short name: database file name and log prefix, e.g. "tumbler". */
	name: string;
	/** The Worker's Hono app (its default export). */
	app: FetchApp;
	/** Absolute path of the app's migrations directory. */
	migrationsDir: string;
	/** Absolute path of the built web app (contains index.html and _headers). */
	staticDir: string;
	defaultPort: number;
	/** Shown in the first-admin hint, e.g. "tumbler" for `./install.sh setup-admin --app tumbler`. */
	installerApp: string;
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
const MAX_BODY = 16 * 1024 * 1024;

function flag(v: string | undefined, fallback: boolean): boolean {
	if (v === undefined || v === "") return fallback;
	return v === "1" || v.toLowerCase() === "true";
}

function writePrivate(path: string, value: string) {
	writeFileSync(path, value + "\n", { mode: 0o600 });
	chmodSync(path, 0o600);
}

/** SERVER_SECRET from the environment, or from a file generated on first start. */
function serverSecret(dataDir: string, log: (m: string) => void): string {
	const env = process.env.SERVER_SECRET;
	if (env) return env;
	const path = join(dataDir, "server-secret");
	if (existsSync(path)) return readFileSync(path, "utf8").trim();
	writePrivate(path, randomBytes(32).toString("base64url"));
	log(`generated SERVER_SECRET in ${path} (back it up with the database; every login depends on it)`);
	return readFileSync(path, "utf8").trim();
}

function clientIp(req: Request, socketIp: string | undefined, trustProxy: boolean): string {
	if (trustProxy) {
		const custom = process.env.CLIENT_IP_HEADER;
		const v = custom ? req.headers.get(custom)?.trim() : req.headers.get("X-Forwarded-For")?.split(",").at(-1)?.trim();
		if (v) return v;
	}
	return socketIp ?? "unknown";
}

function publicOrigin(req: Request, fixed: string | null, trustProxy: boolean): string {
	if (fixed) return fixed;
	const u = new URL(req.url);
	if (trustProxy) {
		const proto = req.headers.get("X-Forwarded-Proto")?.split(",")[0]?.trim();
		const host = req.headers.get("X-Forwarded-Host")?.split(",")[0]?.trim() ?? req.headers.get("Host");
		if ((proto === "http" || proto === "https") && host) return `${proto}://${host}`;
	}
	return u.origin;
}

export async function runStandalone(o: StandaloneOptions) {
	const log = (m: string) => console.log(`[${o.name}] ${m}`);
	const dataDir = resolve(process.env.DATA_DIR || "data");
	mkdirSync(dataDir, { recursive: true, mode: 0o700 });
	const dbPath = process.env.DATABASE_PATH
		? isAbsolute(process.env.DATABASE_PATH)
			? process.env.DATABASE_PATH
			: resolve(process.env.DATABASE_PATH)
		: join(dataDir, `${o.name}.sqlite`);
	const host = process.env.HOST || "127.0.0.1";
	const port = Number(process.env.PORT || o.defaultPort);
	const trustProxy = flag(process.env.TRUST_PROXY, LOOPBACK.has(host));
	const fixedOrigin = process.env.PUBLIC_URL ? new URL(process.env.PUBLIC_URL).origin : null;

	if (!existsSync(join(o.staticDir, "index.html"))) {
		throw new Error(`No built web app in ${o.staticDir}. Run: bun run build:standalone`);
	}
	if (fixedOrigin?.startsWith("http:") && !LOOPBACK.has(new URL(fixedOrigin).hostname)) {
		log(`warning: PUBLIC_URL is plain http. Browsers only keep the __Host- session cookie over https; put a TLS proxy in front.`);
	}

	const db = new SqliteD1(dbPath);
	migrate(db, o.migrationsDir, log);

	const SERVER_SECRET = serverSecret(dataDir, log);
	if (SERVER_SECRET.length < 32) throw new Error("SERVER_SECRET must be at least 32 characters");
	const tokenPath = join(dataDir, "admin-setup-token");
	const users = (db.sqlite.query("SELECT COUNT(*) AS n FROM users").get() as { n: number }).n;
	let ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN ?? "";
	if (users > 0) rmSync(tokenPath, { force: true });
	else if (!ADMIN_SETUP_TOKEN) {
		ADMIN_SETUP_TOKEN = randomBytes(32).toString("base64url");
		writePrivate(tokenPath, ADMIN_SETUP_TOKEN);
	}

	const env = { DB: db, SERVER_SECRET, ADMIN_SETUP_TOKEN };
	const site = new StaticSite(o.staticDir);
	const pending = new Set<Promise<unknown>>();
	const ctx: ExecutionContext = {
		waitUntil(p) {
			const t = p.catch((e) => console.error(e)).finally(() => pending.delete(t));
			pending.add(t);
		},
		passThroughOnException() {},
		props: {},
	};

	const server = Bun.serve({
		hostname: host,
		port,
		maxRequestBodySize: MAX_BODY,
		development: false,
		async fetch(req, srv) {
			const url = new URL(req.url);
			if (url.pathname !== "/api" && !url.pathname.startsWith("/api/")) {
				return site.respond(req, url.pathname) ?? new Response("Not found", { status: req.method === "GET" || req.method === "HEAD" ? 404 : 405 });
			}
			// Rebuild the request as the Worker would see it: public origin, and the client IP in the
			// header the accounts code reads. A client-sent CF-Connecting-IP is always replaced.
			const headers = new Headers(req.headers);
			headers.set("CF-Connecting-IP", clientIp(req, srv.requestIP(req)?.address, trustProxy));
			const origin = publicOrigin(req, fixedOrigin, trustProxy);
			const inner = new Request(origin + url.pathname + url.search, {
				method: req.method,
				headers,
				body: req.method === "GET" || req.method === "HEAD" ? null : req.body,
				redirect: "manual",
			});
			return o.app.fetch(inner, env as never, ctx as never);
		},
		error(err) {
			console.error(err);
			return Response.json({ error: "internal_error" }, { status: 500 });
		},
	});

	log(`listening on http://${host}:${server.port} (database ${dbPath}${fixedOrigin ? `, public ${fixedOrigin}` : ""})`);
	if (users === 0) {
		const url = fixedOrigin ?? `http://localhost:${server.port}`;
		const prefix = o.installerApp.toUpperCase();
		log(
			process.env.ADMIN_SETUP_TOKEN
				? `no users yet: create the first admin with ${prefix}_SETUP_TOKEN=<ADMIN_SETUP_TOKEN> ./install.sh setup-admin --app ${o.installerApp} --url ${url}`
				: `no users yet: create the first admin with ${prefix}_SETUP_TOKEN="$(cat ${tokenPath})" ./install.sh setup-admin --app ${o.installerApp} --url ${url}`,
		);
	}

	let stopping = false;
	const shutdown = async (signal: string) => {
		if (stopping) return;
		stopping = true;
		log(`${signal}: finishing open requests`);
		await server.stop();
		await Promise.allSettled([...pending]);
		db.close();
		process.exit(0);
	};
	process.on("SIGINT", () => void shutdown("SIGINT"));
	process.on("SIGTERM", () => void shutdown("SIGTERM"));
	return server;
}
