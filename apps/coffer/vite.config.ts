import { cloudflare } from "@cloudflare/vite-plugin";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// The dashboard is online-only (it talks to the API for everything), so no service worker.
export default defineConfig({
	plugins: [preact(), tailwindcss(), cloudflare()],
});
