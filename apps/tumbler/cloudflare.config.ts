import { bindings, defineConfig } from "cf/config";
import * as entrypoint from "./worker/index.ts" with { type: "cf-worker" };

// Evaluated by cf in Node.js; declared here so the Worker tsconfig needs no Node types.
declare const process: { env: Record<string, string | undefined> };

// Deployment settings come from the environment so one config serves every install.
// The installer sets them; none of them are secrets.
//   CLOUDFLARE_ACCOUNT_ID  account to deploy to
//   TUMBLER_D1_ID          D1 database ID (found or created by the installer)
//   TUMBLER_DOMAIN         optional custom domain, e.g. tumbler.example.com (zone must be in the account)
const d1Id = process.env.TUMBLER_D1_ID || undefined;
const domain = process.env.TUMBLER_DOMAIN || undefined;

export default defineConfig({
	accountId: process.env.CLOUDFLARE_ACCOUNT_ID || undefined,
	worker: {
		name: "tumbler",
		compatibilityDate: "2026-11-01",
		entrypoint,
		assets: {
			// Static PWA is served directly; only /api/* reaches the Worker.
			notFoundHandling: "single-page-application",
			runWorkerFirst: ["/api/*"],
		},
		// With a custom domain, serve only there: one origin for cookies and CSP.
		...(domain ? { domains: [domain], workersDev: false } : {}),
		env: {
			DB: bindings.d1({ name: "tumbler-db", ...(d1Id ? { id: d1Id } : {}) }),
			// Server-side pepper: HMAC key for auth verifiers and decoy pre-login salts,
			// and encryption key for account-login TOTP secrets. Must never change after install.
			SERVER_SECRET: bindings.secret(),
			// One-time token for creating the first admin (POST /api/setup). Useless once any user exists.
			ADMIN_SETUP_TOKEN: bindings.secret(),
		},
	},
});
