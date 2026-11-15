// Static files of the built web app, served like Workers static assets: the `_headers` file applies,
// unknown paths without a file extension get index.html (single-page application), and everything is
// loaded into memory once at startup with precomputed ETags and brotli/gzip variants.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, sep } from "node:path";
import { brotliCompressSync, constants, gzipSync } from "node:zlib";

type Bytes = Uint8Array<ArrayBuffer>;

interface Asset {
	body: Bytes;
	br?: Bytes;
	gzip?: Bytes;
	type: string;
	etag: string;
	headers: [string, string][];
}

interface HeaderRule {
	pattern: RegExp;
	headers: [string, string][];
}

const TYPES: Record<string, string> = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".mjs": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".webmanifest": "application/manifest+json; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".ico": "image/x-icon",
	".webp": "image/webp",
	".woff2": "font/woff2",
	".txt": "text/plain; charset=utf-8",
	".map": "application/json; charset=utf-8",
};
const COMPRESSIBLE = /^(text\/|application\/(json|manifest\+json|javascript)|image\/svg\+xml)/;

/** Parses a Cloudflare `_headers` file: an unindented URL pattern, then indented `Name: value` lines. */
export function parseHeaders(text: string): HeaderRule[] {
	const rules: HeaderRule[] = [];
	let current: HeaderRule | null = null;
	for (const raw of text.split(/\r?\n/)) {
		if (!raw.trim() || raw.trim().startsWith("#")) continue;
		if (!/^\s/.test(raw)) {
			const src = raw
				.trim()
				.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
				.replace(/\*/g, ".*")
				.replace(/:[A-Za-z]\w*/g, "[^/]+");
			current = { pattern: new RegExp(`^${src}$`), headers: [] };
			rules.push(current);
			continue;
		}
		const i = raw.indexOf(":");
		if (current && i > 0) current.headers.push([raw.slice(0, i).trim(), raw.slice(i + 1).trim()]);
	}
	return rules;
}

function walk(dir: string): string[] {
	return readdirSync(dir).flatMap((name) => {
		const p = join(dir, name);
		return statSync(p).isDirectory() ? walk(p) : [p];
	});
}

export class StaticSite {
	private readonly assets = new Map<string, Asset>();
	private readonly rules: HeaderRule[];

	constructor(readonly dir: string) {
		let headersFile = "";
		try {
			headersFile = readFileSync(join(dir, "_headers"), "utf8");
		} catch {
			// no _headers
		}
		this.rules = parseHeaders(headersFile);
		for (const file of walk(dir)) {
			const path = "/" + relative(dir, file).split(sep).join("/");
			if (path === "/_headers" || path === "/_redirects") continue;
			this.assets.set(path, this.load(path, file));
		}
		if (!this.assets.has("/index.html")) throw new Error(`${dir} has no index.html`);
	}

	private load(path: string, file: string): Asset {
		const body: Bytes = new Uint8Array(readFileSync(file));
		const type = TYPES[extname(file).toLowerCase()] ?? "application/octet-stream";
		const asset: Asset = {
			body,
			type,
			etag: `"${createHash("sha256").update(body).digest("base64url").slice(0, 22)}"`,
			headers: [],
		};
		// Several matching rules: values of the same header are joined, as on Workers.
		const h = new Headers();
		for (const r of this.rules) if (r.pattern.test(path)) for (const [k, v] of r.headers) h.append(k, v);
		// Vite fingerprints everything under /assets/; anything else must be revalidated.
		if (!h.has("Cache-Control")) {
			h.set("Cache-Control", path.startsWith("/assets/") ? "public, max-age=31536000, immutable" : "public, max-age=0, must-revalidate");
		}
		asset.headers = [...h];
		if (COMPRESSIBLE.test(type) && body.length > 512) {
			const br = brotliCompressSync(body, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } });
			const gz = gzipSync(body, { level: 9 });
			if (br.length < body.length) asset.br = new Uint8Array(br);
			if (gz.length < body.length) asset.gzip = new Uint8Array(gz);
		}
		return asset;
	}

	/** Returns null when the request is not for a static file (caller answers 404 or 405). */
	respond(req: Request, pathname: string): Response | null {
		if (req.method !== "GET" && req.method !== "HEAD") return null;
		let path: string;
		try {
			path = decodeURIComponent(pathname);
		} catch {
			return null;
		}
		if (path.endsWith("/")) path += "index.html";
		let asset = this.assets.get(path);
		// Single-page application: client routes (no file extension) get the app shell.
		if (!asset && !/\.[A-Za-z0-9]+$/.test(path)) asset = this.assets.get("/index.html");
		if (!asset) return null;

		const headers = new Headers(asset.headers);
		headers.set("Content-Type", asset.type);
		headers.set("ETag", asset.etag);
		if (asset.br || asset.gzip) headers.set("Vary", "Accept-Encoding");
		if (req.headers.get("If-None-Match") === asset.etag) return new Response(null, { status: 304, headers });

		const accept = req.headers.get("Accept-Encoding") ?? "";
		let body = asset.body;
		if (asset.br && /\bbr\b/.test(accept)) {
			body = asset.br;
			headers.set("Content-Encoding", "br");
		} else if (asset.gzip && /\bgzip\b/.test(accept)) {
			body = asset.gzip;
			headers.set("Content-Encoding", "gzip");
		}
		headers.set("Content-Length", String(body.length));
		return new Response(req.method === "HEAD" ? null : body, { headers });
	}
}
