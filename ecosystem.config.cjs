// pm2 process file for standalone mode (Bun + SQLite, no Cloudflare).
//
//   bun install && bun run build:standalone
//   pm2 start ecosystem.config.cjs            # or: pm2 start ecosystem.config.cjs --only tumbler
//   pm2 save && pm2 startup                   # start on boot
//
// One fork-mode process per app: SQLite has a single writer, so do not use cluster mode or
// instances > 1. Put a TLS reverse proxy in front and set PUBLIC_URL to its https origin.
// Secrets: SERVER_SECRET is generated into DATA_DIR on first start (or set it in apps/<app>/.env).
// Configuration reference: packages/standalone/src/server.ts.
const { join } = require("node:path");

const app = (name, port, publicUrl) => ({
	name,
	cwd: join(__dirname, "apps", name),
	script: "server.ts",
	interpreter: "bun",
	exec_mode: "fork",
	instances: 1,
	autorestart: true,
	max_restarts: 20,
	min_uptime: "10s",
	exp_backoff_restart_delay: 200,
	// SIGINT first; the server finishes open requests and closes the database.
	kill_timeout: 10_000,
	max_memory_restart: "300M",
	time: true,
	env: {
		NODE_ENV: "production",
		HOST: "127.0.0.1",
		PORT: String(port),
		DATA_DIR: join(__dirname, "data", name),
		PUBLIC_URL: publicUrl,
	},
});

module.exports = {
	apps: [
		app("tumbler", 8701, process.env.TUMBLER_PUBLIC_URL || ""),
		app("coffer", 8702, process.env.COFFER_PUBLIC_URL || ""),
	],
};
