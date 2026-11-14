import { HttpError } from "@cfsa/server-kit";
import { adminRoutes, authRoutes, createApp } from "@cfsa/worker-accounts";
import { machineRoutes } from "./machine.ts";
import { projectRoutes } from "./projects.ts";

// API only. Static assets (the dashboard) are served by the assets layer before this Worker runs.
// The cookie name and AAD prefix must not change once deployed.
const app = createApp({ appName: "Coffer", cookie: "__Host-coffer_session", aadPrefix: "coffer" });

app.get("/health", (c) => c.json({ ok: true, time: Date.now() }));
authRoutes(app);
adminRoutes(app);
projectRoutes(app);
machineRoutes(app);
app.all("*", () => {
	throw new HttpError(404, "not_found");
});

export default app satisfies ExportedHandler<Env>;
