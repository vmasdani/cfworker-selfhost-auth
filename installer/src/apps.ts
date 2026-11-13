// App registry: everything the installer can install. Data only; the installer reads it.
//
// Local apps live in this repo and deploy with `cf`.
// External apps are fetched from upstream at a pinned commit and deploy with the
// tool their own repo is configured for (see AGENTS.md: one CLI per project).

export type Resource =
	| { type: "d1"; name: string; binding: string }
	| { type: "r2"; name: string; binding: string }
	| { type: "kv"; name: string; binding: string };

export interface SecretDef {
	name: string;
	/** How the installer generates a value when none exists. Never printed. */
	generate: "random-base64-32";
	minLength?: number;
}

export interface Variant {
	id: string;
	label: string;
	resources: Resource[];
	/** Command run inside the app directory to deploy this variant. */
	deploy: string[];
	notes?: string[];
}

export type FirstAdmin =
	/** Installer generates credentials + recovery key locally, inserts into D1, prints them once. */
	| { kind: "installer-bootstrap" }
	/**
	 * Installer registers the first account through the app's Bitwarden-compatible
	 * `POST /api/accounts/register` right after deploy, using client-side Bitwarden key
	 * derivation, with an admin login and master password the user chooses. The first registered
	 * user becomes admin, so this closes the window in which anyone else could claim it.
	 */
	| { kind: "bitwarden-register"; endpoint: string };

export interface AppDef {
	id: string;
	name: string;
	description: string;
	source:
		| { kind: "local"; dir: string }
		| { kind: "git"; repo: string; tag: string; commit: string; license: string };
	cli: "cf" | "wrangler";
	workerName: string;
	variants: Variant[];
	secrets: SecretDef[];
	firstAdmin: FirstAdmin;
	notes: string[];
}

export const APPS: AppDef[] = [
	{
		id: "tumbler",
		name: "Tumbler Authenticator",
		description: "Offline-capable PWA TOTP authenticator with end-to-end encrypted sync.",
		source: { kind: "local", dir: "apps/tumbler" },
		cli: "cf",
		workerName: "tumbler",
		variants: [
			{
				id: "default",
				label: "D1",
				resources: [{ type: "d1", name: "tumbler-db", binding: "DB" }],
				deploy: ["cf", "deploy"],
			},
		],
		secrets: [{ name: "SERVER_SECRET", generate: "random-base64-32" }],
		firstAdmin: { kind: "installer-bootstrap" },
		notes: [],
	},
	{
		id: "nodewarden",
		name: "NodeWarden",
		description: "Third-party Bitwarden-compatible password manager server for Workers (official Bitwarden clients work).",
		source: {
			kind: "git",
			repo: "https://github.com/shuaiplus/NodeWarden.git",
			tag: "v1.8.1",
			// Pin the commit, not just the tag: tags can be moved upstream.
			commit: "e92c91e771fac13c54042902d64d015514daa9ad",
			license: "LGPL-3.0",
		},
		// Upstream ships wrangler.toml, so it deploys with Wrangler (run via npx, not added to this repo).
		cli: "wrangler",
		workerName: "nodewarden",
		variants: [
			{
				id: "r2",
				label: "R2 attachments (upstream default; R2 must be enabled on the account)",
				resources: [
					{ type: "d1", name: "nodewarden-db", binding: "DB" },
					{ type: "r2", name: "nodewarden-attachments", binding: "ATTACHMENTS" },
				],
				deploy: ["npm", "run", "deploy"],
			},
			{
				id: "kv",
				label: "KV attachments (no R2 needed; 25 MiB per file)",
				resources: [{ type: "d1", name: "nodewarden-db", binding: "DB" }],
				deploy: ["npm", "run", "deploy:kv"],
				notes: ["Upstream script scripts/ensure-kv.cjs creates the KV namespace."],
			},
		],
		secrets: [{ name: "JWT_SECRET", generate: "random-base64-32", minLength: 32 }],
		firstAdmin: { kind: "bitwarden-register", endpoint: "/api/accounts/register" },
		notes: [
			"Database schema is created by the Worker at runtime; no migration step.",
			"Uses Durable Objects (SQLite-backed) and a */5 min cron trigger.",
			"After install, enable TOTP 2FA on the account (store it in Tumbler).",
			"Further users join with invite codes created by the admin.",
			"Not affiliated with Bitwarden. Report issues to NodeWarden, not Bitwarden.",
		],
	},
];
