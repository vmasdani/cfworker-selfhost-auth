// Tumbler service worker. Precache list and version are injected at build time (see vite.config.ts).
// Cache-first for the app shell so the PWA works fully offline. /api/* always goes to the network.
// ignoreVary: module scripts are requested with an Origin header the precache request lacks.

const VERSION = "__VERSION__";
const PRECACHE = __PRECACHE__;
const CACHE = `tumbler-${VERSION}`;

self.addEventListener("install", (event) => {
	event.waitUntil(
		caches.open(CACHE).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()),
	);
});

self.addEventListener("activate", (event) => {
	event.waitUntil(
		caches.keys()
			.then((keys) => Promise.all(keys.filter((k) => k.startsWith("tumbler-") && k !== CACHE).map((k) => caches.delete(k))))
			.then(() => self.clients.claim()),
	);
});

self.addEventListener("fetch", (event) => {
	const req = event.request;
	const url = new URL(req.url);
	if (req.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;

	if (req.mode === "navigate") {
		event.respondWith(caches.match("/", { cacheName: CACHE, ignoreVary: true }).then((hit) => hit ?? fetch(req)));
		return;
	}
	event.respondWith(caches.match(req, { cacheName: CACHE, ignoreVary: true }).then((hit) => hit ?? fetch(req)));
});
