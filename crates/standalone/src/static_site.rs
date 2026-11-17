//! Static files of the built web app, served like Workers static assets (port of
//! `packages/standalone/src/static.ts`): the `_headers` file applies, unknown paths without a file
//! extension get index.html (single-page application), and everything is loaded into memory once at
//! startup with precomputed ETags and brotli/gzip variants.

use cfsa_core::crypto::{sha256, to_b64url};
use cfsa_core::http::Resp;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

struct Asset {
	body: Vec<u8>,
	br: Option<Vec<u8>>,
	gzip: Option<Vec<u8>>,
	content_type: &'static str,
	etag: String,
	headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
	Lit(String),
	Star,
	Param,
}

struct Rule {
	pattern: Vec<Tok>,
	headers: Vec<(String, String)>,
}

fn content_type(path: &str) -> &'static str {
	let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
	match ext.as_str() {
		"html" => "text/html; charset=utf-8",
		"js" | "mjs" => "text/javascript; charset=utf-8",
		"css" => "text/css; charset=utf-8",
		"json" | "map" => "application/json; charset=utf-8",
		"webmanifest" => "application/manifest+json; charset=utf-8",
		"svg" => "image/svg+xml",
		"png" => "image/png",
		"ico" => "image/x-icon",
		"webp" => "image/webp",
		"woff2" => "font/woff2",
		"txt" => "text/plain; charset=utf-8",
		_ => "application/octet-stream",
	}
}

fn compressible(t: &str) -> bool {
	t.starts_with("text/")
		|| t.starts_with("application/json")
		|| t.starts_with("application/manifest+json")
		|| t.starts_with("application/javascript")
		|| t.starts_with("image/svg+xml")
}

/// `*` matches anything, `:name` one path segment, everything else literally.
fn compile(src: &str) -> Vec<Tok> {
	let mut out = Vec::new();
	let mut lit = String::new();
	let mut chars = src.chars().peekable();
	while let Some(c) = chars.next() {
		if c == '*' {
			if !lit.is_empty() {
				out.push(Tok::Lit(std::mem::take(&mut lit)));
			}
			out.push(Tok::Star);
		} else if c == ':' && chars.peek().is_some_and(|n| n.is_ascii_alphabetic()) {
			if !lit.is_empty() {
				out.push(Tok::Lit(std::mem::take(&mut lit)));
			}
			while chars.peek().is_some_and(|n| n.is_ascii_alphanumeric() || *n == '_') {
				chars.next();
			}
			out.push(Tok::Param);
		} else {
			lit.push(c);
		}
	}
	if !lit.is_empty() {
		out.push(Tok::Lit(lit));
	}
	out
}

fn matches(p: &[Tok], s: &str) -> bool {
	match p.first() {
		None => s.is_empty(),
		Some(Tok::Lit(l)) => s.strip_prefix(l.as_str()).is_some_and(|rest| matches(&p[1..], rest)),
		Some(Tok::Star) => (0..=s.len()).filter(|&i| s.is_char_boundary(i)).any(|i| matches(&p[1..], &s[i..])),
		Some(Tok::Param) => {
			let seg = s.find('/').unwrap_or(s.len());
			(1..=seg).filter(|&i| s.is_char_boundary(i)).any(|i| matches(&p[1..], &s[i..]))
		}
	}
}

/// Parses a Cloudflare `_headers` file: an unindented URL pattern, then indented `Name: value` lines.
fn parse_headers(text: &str) -> Vec<Rule> {
	let mut rules: Vec<Rule> = Vec::new();
	for raw in text.lines() {
		let t = raw.trim();
		if t.is_empty() || t.starts_with('#') {
			continue;
		}
		if !raw.starts_with(char::is_whitespace) {
			rules.push(Rule { pattern: compile(t), headers: Vec::new() });
			continue;
		}
		if let (Some(rule), Some(i)) = (rules.last_mut(), raw.find(':'))
			&& i > 0
		{
			rule.headers.push((raw[..i].trim().to_string(), raw[i + 1..].trim().to_string()));
		}
	}
	rules
}

pub struct StaticSite {
	assets: HashMap<String, Asset>,
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
	for e in std::fs::read_dir(dir)? {
		let p = e?.path();
		if p.is_dir() { walk(&p, out)? } else { out.push(p) }
	}
	Ok(())
}

fn brotli(body: &[u8]) -> Vec<u8> {
	let mut out = Vec::new();
	{
		let mut w = brotli::CompressorWriter::new(&mut out, 4096, 11, 22);
		let _ = w.write_all(body);
	}
	out
}

fn gzip(body: &[u8]) -> Vec<u8> {
	let mut w = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
	let _ = w.write_all(body);
	w.finish().unwrap_or_default()
}

impl StaticSite {
	pub fn load(dir: &Path) -> Result<StaticSite, String> {
		let rules = parse_headers(&std::fs::read_to_string(dir.join("_headers")).unwrap_or_default());
		let mut files = Vec::new();
		walk(dir, &mut files).map_err(|e| format!("{}: {e}", dir.display()))?;
		let mut assets = HashMap::new();
		for file in files {
			let rel = file.strip_prefix(dir).map_err(|e| e.to_string())?;
			let path = format!("/{}", rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/"));
			if path == "/_headers" || path == "/_redirects" {
				continue;
			}
			let body = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
			let ct = content_type(&path);
			// Several matching rules: values of the same header are joined, as on Workers.
			let mut headers: Vec<(String, String)> = Vec::new();
			for r in rules.iter().filter(|r| matches(&r.pattern, &path)) {
				for (k, v) in &r.headers {
					let k = k.to_ascii_lowercase();
					match headers.iter_mut().find(|(n, _)| *n == k) {
						Some((_, existing)) => {
							existing.push_str(", ");
							existing.push_str(v);
						}
						None => headers.push((k, v.clone())),
					}
				}
			}
			// Vite fingerprints everything under /assets/; anything else must be revalidated.
			if !headers.iter().any(|(k, _)| k == "cache-control") {
				let cc =
					if path.starts_with("/assets/") { "public, max-age=31536000, immutable" } else { "public, max-age=0, must-revalidate" };
				headers.push(("cache-control".into(), cc.into()));
			}
			let (mut br, mut gz) = (None, None);
			if compressible(ct) && body.len() > 512 {
				let b = brotli(&body);
				let g = gzip(&body);
				if b.len() < body.len() {
					br = Some(b);
				}
				if g.len() < body.len() {
					gz = Some(g);
				}
			}
			let etag = format!("\"{}\"", &to_b64url(&sha256(&body))[..22]);
			assets.insert(path, Asset { body, br, gzip: gz, content_type: ct, etag, headers });
		}
		if !assets.contains_key("/index.html") {
			return Err(format!("{} has no index.html", dir.display()));
		}
		Ok(StaticSite { assets })
	}

	/// None when the request is not for a static file (the caller answers 404 or 405).
	pub fn respond(&self, method: &str, pathname: &str, if_none_match: Option<&str>, accept_encoding: &str) -> Option<Resp> {
		if method != "GET" && method != "HEAD" {
			return None;
		}
		let mut path = cfsa_core::text::percent_decode(pathname, false)?;
		if path.ends_with('/') {
			path.push_str("index.html");
		}
		let has_ext = path.rsplit_once('.').is_some_and(|(_, e)| !e.is_empty() && e.bytes().all(|b| b.is_ascii_alphanumeric()));
		let asset = self.assets.get(&path).or_else(|| if has_ext { None } else { self.assets.get("/index.html") })?;

		let mut headers = asset.headers.clone();
		headers.push(("content-type".into(), asset.content_type.into()));
		headers.push(("etag".into(), asset.etag.clone()));
		if asset.br.is_some() || asset.gzip.is_some() {
			headers.push(("vary".into(), "Accept-Encoding".into()));
		}
		if if_none_match == Some(asset.etag.as_str()) {
			return Some(Resp { status: 304, headers, body: Vec::new() });
		}
		let word = |w: &str| accept_encoding.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| t == w);
		let body = match (&asset.br, &asset.gzip) {
			(Some(b), _) if word("br") => {
				headers.push(("content-encoding".into(), "br".into()));
				b
			}
			(_, Some(g)) if word("gzip") => {
				headers.push(("content-encoding".into(), "gzip".into()));
				g
			}
			_ => &asset.body,
		};
		headers.push(("content-length".into(), body.len().to_string()));
		Some(Resp { status: 200, headers, body: if method == "HEAD" { Vec::new() } else { body.clone() } })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn header_patterns() {
		let r = parse_headers("/*\n  X-A: 1\n/sw.js\n  Cache-Control: no-cache\n/u/:id/x\n  X-B: 2\n");
		assert!(matches(&r[0].pattern, "/anything/here"));
		assert!(matches(&r[1].pattern, "/sw.js"));
		assert!(!matches(&r[1].pattern, "/swxjs"));
		assert!(matches(&r[2].pattern, "/u/42/x"));
		assert!(!matches(&r[2].pattern, "/u/4/2/x"));
		assert_eq!(r[1].headers, vec![("Cache-Control".to_string(), "no-cache".to_string())]);
	}
}
