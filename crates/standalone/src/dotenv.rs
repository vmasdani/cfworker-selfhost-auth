//! The environment the Bun server sees: the process environment over `.env` files in the working
//! directory, loaded like Bun does (`.env`, then `.env.<NODE_ENV>`, then `.env.local`; later wins,
//! the process environment wins over all). `.env.local` is skipped when NODE_ENV is `test`.

use std::collections::HashMap;

pub struct Config(HashMap<String, String>);

impl Config {
	pub fn load() -> Config {
		let mut m: HashMap<String, String> = HashMap::new();
		let node_env = std::env::var("NODE_ENV").unwrap_or_else(|_| "development".into());
		let mut files = vec![".env".to_string(), format!(".env.{node_env}")];
		if node_env != "test" {
			files.push(".env.local".into());
		}
		for f in files {
			if let Ok(text) = std::fs::read_to_string(&f) {
				m.extend(parse(&text));
			}
		}
		m.extend(std::env::vars());
		Config(m)
	}

	/// The value, or None when unset or empty.
	pub fn get(&self, k: &str) -> Option<&str> {
		self.0.get(k).map(String::as_str).filter(|v| !v.is_empty())
	}
}

pub fn parse(text: &str) -> Vec<(String, String)> {
	let mut out = Vec::new();
	for line in text.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let line = line.strip_prefix("export ").unwrap_or(line);
		let Some((k, v)) = line.split_once('=') else { continue };
		let v = v.trim();
		let v = if v.len() >= 2 && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\'')) {
			let inner = &v[1..v.len() - 1];
			if v.starts_with('"') { inner.replace("\\n", "\n") } else { inner.to_string() }
		} else {
			v.split(" #").next().unwrap_or("").trim().to_string()
		};
		out.push((k.trim().to_string(), v));
	}
	out
}

#[cfg(test)]
mod tests {
	#[test]
	fn parses() {
		let p = super::parse("# c\nA=1\nexport B = \"x y\"\nC='z' \nD=v # note\n\nbad");
		assert_eq!(p, vec![("A".into(), "1".into()), ("B".into(), "x y".into()), ("C".into(), "z".into()), ("D".into(), "v".into())]);
	}
}
