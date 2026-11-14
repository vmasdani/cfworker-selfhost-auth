// Minimal .env parsing and formatting (the common subset: KEY=value, quotes, comments, `export`).

export interface DotenvResult {
	entries: [string, string][];
	errors: string[];
}

const LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)?$/;

export function parseDotenv(text: string): DotenvResult {
	const entries: [string, string][] = [];
	const errors: string[] = [];
	const lines = text.replace(/\r\n?/g, "\n").split("\n");
	for (let i = 0; i < lines.length; i++) {
		const line = lines[i]!;
		if (!line.trim() || line.trim().startsWith("#")) continue;
		const m = LINE.exec(line);
		if (!m) {
			errors.push(`Line ${i + 1}: not KEY=value`);
			continue;
		}
		let rest = (m[2] ?? "").trim();
		let value: string;
		if (rest.startsWith('"')) {
			// Double quotes: may span lines; supports \n \r \t \" \\ escapes.
			let raw = rest.slice(1);
			while (closingQuote(raw) < 0 && i + 1 < lines.length) raw += "\n" + lines[++i];
			const end = closingQuote(raw);
			if (end < 0) {
				errors.push(`${m[1]}: missing closing quote`);
				continue;
			}
			value = raw.slice(0, end).replace(/\\([nrt"\\])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" })[c]!);
		} else if (rest.startsWith("'")) {
			const end = rest.indexOf("'", 1);
			if (end < 0) {
				errors.push(`${m[1]}: missing closing quote`);
				continue;
			}
			value = rest.slice(1, end);
		} else {
			const hash = rest.search(/\s#/);
			if (hash >= 0) rest = rest.slice(0, hash);
			value = rest.trim();
		}
		entries.push([m[1]!, value]);
	}
	return { entries, errors };
}

function closingQuote(s: string): number {
	for (let i = 0; i < s.length; i++) {
		if (s[i] === "\\") i++;
		else if (s[i] === '"') return i;
	}
	return -1;
}

export function formatDotenv(entries: [string, string][]): string {
	return entries
		.map(([k, v]) => {
			if (/^[A-Za-z0-9_./:@+,=-]*$/.test(v)) return `${k}=${v}`;
			return `${k}="${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r")}"`;
		})
		.join("\n")
		.concat(entries.length ? "\n" : "");
}
