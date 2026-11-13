import { HttpError } from "@cfsa/server-kit";
import { adminRoutes } from "./admin.ts";
import { createApp } from "./app.ts";
import { authRoutes } from "./auth.ts";
import { syncRoutes } from "./sync.ts";

// API only. Static assets (the PWA) are served by the assets layer before this Worker runs.
const app = createApp();

app.get("/health", (c) => c.json({ ok: true, time: Date.now() }));
authRoutes(app);
syncRoutes(app);
adminRoutes(app);
app.all("*", () => {
	throw new HttpError(404, "not_found");
});

export default app satisfies ExportedHandler<Env>;
