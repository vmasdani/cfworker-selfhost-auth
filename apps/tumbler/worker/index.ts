import { HttpError } from "@cfsa/server-kit";
import { adminRoutes, authRoutes, createApp } from "@cfsa/worker-accounts";
import { syncRoutes } from "./sync.ts";

// API only. Static assets (the PWA) are served by the assets layer before this Worker runs.
// The cookie name and AAD prefix must not change: existing sessions and login TOTP secrets use them.
const app = createApp({ appName: "Tumbler", cookie: "__Host-tumbler_session", aadPrefix: "tumbler" });

app.get("/health", (c) => c.json({ ok: true, time: Date.now() }));
authRoutes(app);
syncRoutes(app);
adminRoutes(app);
app.all("*", () => {
	throw new HttpError(404, "not_found");
});

export default app satisfies ExportedHandler<Env>;
