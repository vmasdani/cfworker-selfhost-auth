import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./worker/index.ts" with { type: "cf-worker" };

export default defineConfig({
	worker: {
		name: "tumbler",
		compatibilityDate: "2026-11-01",
		entrypoint,
		assets: {
			// Static PWA is served directly; only /api/* reaches the Worker.
			notFoundHandling: "single-page-application",
			runWorkerFirst: ["/api/*"],
		},
		env: {
			DB: bindings.d1({ name: "tumbler-db" }),
			// Server-side pepper: HMAC key for auth verifiers and decoy pre-login salts,
			// and encryption key for account-login TOTP secrets.
			SERVER_SECRET: bindings.secret(),
		},
	},
});
