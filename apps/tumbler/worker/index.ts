import { Hono } from "hono";

// API only. Static assets (the PWA) are served by the assets layer before this Worker runs.
const app = new Hono<{ Bindings: Env }>().basePath("/api");

app.get("/health", (c) => c.json({ ok: true, time: Date.now() }));

app.all("*", (c) => c.json({ error: "not_found" }, 404));

export default app satisfies ExportedHandler<Env>;
