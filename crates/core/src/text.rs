//! JavaScript string semantics the TypeScript code relies on, plus URL encodings.

/// `String.prototype.length`: UTF-16 code units.
pub fn js_len(s: &str) -> usize {
	s.encode_utf16().count()
}

/// `String.prototype.trim()`: Unicode White_Space plus U+FEFF.
pub fn js_trim(s: &str) -> &str {
	s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
	percent_encode(s, |b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b), false)
}

/// `URLSearchParams` serialization of one name or value (application/x-www-form-urlencoded).
pub fn form_encode(s: &str) -> String {
	percent_encode(s, |b| b.is_ascii_alphanumeric() || b"*-._".contains(&b), true)
}

fn percent_encode(s: &str, keep: impl Fn(u8) -> bool, space_plus: bool) -> String {
	let mut out = String::with_capacity(s.len());
	for &b in s.as_bytes() {
		if keep(b) {
			out.push(b as char);
		} else if space_plus && b == b' ' {
			out.push('+');
		} else {
			out.push_str(&format!("%{b:02X}"));
		}
	}
	out
}

/// Percent-decoding (`decodeURIComponent`); `plus_as_space` for query strings. None on invalid UTF-8.
pub fn percent_decode(s: &str, plus_as_space: bool) -> Option<String> {
	let b = s.as_bytes();
	let mut out = Vec::with_capacity(b.len());
	let mut i = 0;
	while i < b.len() {
		match b[i] {
			b'%' if i + 2 < b.len() => {
				let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
				{
					let v = hex?;
					out.push(v);
					i += 3;
				}
			}
			b'%' => return None,
			b'+' if plus_as_space => {
				out.push(b' ');
				i += 1;
			}
			c => {
				out.push(c);
				i += 1;
			}
		}
	}
	String::from_utf8(out).ok()
}

/// `URLSearchParams.get(name)`: the first value, decoded. Undecodable pairs are kept raw.
pub fn query_get(query: &str, name: &str) -> Option<String> {
	for pair in query.split('&').filter(|p| !p.is_empty()) {
		let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
		let k = percent_decode(k, true).unwrap_or_else(|| k.to_string());
		if k == name {
			return Some(percent_decode(v, true).unwrap_or_else(|| v.to_string()));
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn encodings_match_js() {
		assert_eq!(encode_uri_component("Tumbler (a.b:8443)"), "Tumbler%20(a.b%3A8443)");
		assert_eq!(form_encode("Tumbler (a.b:8443)"), "Tumbler+%28a.b%3A8443%29");
		assert_eq!(encode_uri_component("é"), "%C3%A9");
	}

	#[test]
	fn decoding() {
		assert_eq!(percent_decode("a%20b+c", true).as_deref(), Some("a b c"));
		assert_eq!(percent_decode("a+b", false).as_deref(), Some("a+b"));
		assert_eq!(percent_decode("%zz", false), None);
		assert_eq!(percent_decode("%2", false), None);
		assert_eq!(query_get("since=12&x=1", "since").as_deref(), Some("12"));
		assert_eq!(query_get("token=a%2Bb", "token").as_deref(), Some("a+b"));
		assert_eq!(query_get("a=1", "since"), None);
	}

	#[test]
	fn trim_and_len() {
		assert_eq!(js_trim("\u{feff} x \n"), "x");
		assert_eq!(js_len("😀"), 2);
	}
}
