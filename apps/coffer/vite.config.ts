import { cloudflare } from "@cloudflare/vite-plugin";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

// STANDALONE=1 (bun run build:standalone) builds only the web app into dist/ for the Bun server.
const standalone = process.env.STANDALONE === "1";

// The dashboard is online-only (it talks to the API for everything), so no service worker.
export default defineConfig({
	plugins: [preact(), tailwindcss(), ...(standalone ? [] : [cloudflare()])],
});
