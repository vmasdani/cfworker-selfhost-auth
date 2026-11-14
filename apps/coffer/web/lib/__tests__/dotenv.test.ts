import { describe, expect, test } from "bun:test";
import { formatDotenv, parseDotenv } from "../dotenv.ts";

describe("dotenv", () => {
	test("parses the common subset", () => {
		const r = parseDotenv(`# comment
export A=1
B = two words # trailing comment
C="line1\\nline2 \\"q\\" \\\\"
D='single # not a comment'
E=
F="multi
line"
bad line
`);
		expect(r.entries).toEqual([
			["A", "1"],
			["B", "two words"],
			["C", 'line1\nline2 "q" \\'],
			["D", "single # not a comment"],
			["E", ""],
			["F", "multi\nline"],
		]);
		expect(r.errors).toEqual(["Line 9: not KEY=value"]);
	});

	test("format → parse round trip", () => {
		const entries: [string, string][] = [
			["PLAIN", "postgres://u@h:5432/db"],
			["SPACES", "a b"],
			["QUOTES", 'say "hi" \\ back'],
			["NEWLINES", "-----BEGIN KEY-----\nabc\n-----END KEY-----"],
			["HASH", "x #y"],
			["EMPTY", ""],
			["UNICODE", "ünïcødé ✓"],
		];
		expect(parseDotenv(formatDotenv(entries)).entries).toEqual(entries);
	});
});
