export class CancelledError extends Error {
	override name = "CancelledError";
	constructor() {
		super("Cancelled. Nothing was created.");
	}
}

/**
 * Read a line without echoing it (for passwords). On a non-TTY stdin (piped input, CI)
 * it falls back to reading one line.
 */
export function readHidden(question: string): Promise<string> {
	const stdin = process.stdin;
	if (!stdin.isTTY) return Promise.resolve(prompt(question) ?? "");

	process.stderr.write(`${question} `);
	stdin.setRawMode(true);
	stdin.setEncoding("utf8");
	stdin.resume();

	return new Promise((resolve, reject) => {
		let value = "";
		const done = (err?: Error) => {
			stdin.off("data", onData);
			stdin.setRawMode(false);
			stdin.pause();
			process.stderr.write("\n");
			if (err) reject(err);
			else resolve(value);
		};
		const onData = (chunk: string) => {
			for (const ch of chunk) {
				if (ch === "\r" || ch === "\n") return done();
				if (ch === "\u0003" || ch === "\u0004") return done(new CancelledError()); // Ctrl-C, Ctrl-D
				if (ch === "\u007f" || ch === "\b") value = [...value].slice(0, -1).join("");
				else if (ch === "\u0015") value = ""; // Ctrl-U
				else if (ch >= " ") value += ch;
			}
		};
		stdin.on("data", onData);
	});
}
