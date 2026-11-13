import { cloudflare } from "@cloudflare/vite-plugin";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, type Plugin } from "vite";

/** Emits /sw.js with a precache list of every built client asset plus public/ files. */
function serviceWorker(): Plugin {
	return {
		name: "tumbler-service-worker",
		apply: "build",
		enforce: "post",
		applyToEnvironment: (env) => env.name === "client",
		generateBundle(_options, bundle) {
			const built = Object.keys(bundle).filter((f) => !f.endsWith(".map") && f !== "index.html");
			const pub = readdirSync(join(import.meta.dirname, "public")).filter((f) => !f.startsWith("_"));
			const precache = ["/", ...[...built, ...pub].sort().map((f) => `/${f}`)];
			const version = createHash("sha256")
				.update(JSON.stringify(precache))
				.update(String((bundle["index.html"] as { source?: unknown } | undefined)?.source ?? ""))
				.digest("hex")
				.slice(0, 12);
			const source = readFileSync(join(import.meta.dirname, "sw", "sw.js"), "utf8")
				.replace('"__VERSION__"', JSON.stringify(version))
				.replace("__PRECACHE__", JSON.stringify(precache));
			this.emitFile({ type: "asset", fileName: "sw.js", source });
		},
	};
}

export default defineConfig({
	plugins: [preact(), tailwindcss(), cloudflare(), serviceWorker()],
});
