// Standalone mode: this app on Bun + SQLite instead of Workers + D1 (see packages/standalone).
//   bun run build:standalone && bun run start     (or: pm2 start ecosystem.config.cjs from the repo root)
import { runStandalone } from "@cfsa/standalone";
import { join } from "node:path";
import app from "./worker/index.ts";

await runStandalone({
	name: "coffer",
	app,
	migrationsDir: join(import.meta.dir, "migrations"),
	staticDir: join(import.meta.dir, "dist"),
	defaultPort: 8702,
	installerApp: "coffer",
});
