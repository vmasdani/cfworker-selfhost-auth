// Runs every SDK snippet (sdk/coffer.ts, coffer.go, Coffer.cs, Coffer.php) against one server and checks
// that each can read what the others wrote. Toolchains that are not installed are skipped (reported).
//
// Usage: bun run scripts/sdk-matrix.ts <base url> <ADMIN_SETUP_TOKEN>      (EMPTY database, like api-test)
// Override binaries with NODE=, GO=, DOTNET=, PHP= (paths).

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Coffer } from "../sdk/coffer.ts";

const [base, setupToken] = process.argv.slice(2);
if (!base || !setupToken) {
	console.error("Usage: bun run scripts/sdk-matrix.ts <base url> <ADMIN_SETUP_TOKEN>");
	process.exit(2);
}
const SDK = join(import.meta.dir, "..", "sdk");
const work = mkdtempSync(join(tmpdir(), "coffer-sdk-"));
const credFile = join(work, "test.env");

// 1. Accounts, project and a read-write client ID for "dev" (and the API checks).
const setup = Bun.spawnSync(["bun", "run", join(import.meta.dir, "api-test.ts"), base, setupToken], {
	env: { ...process.env, SDK_CREDENTIALS_OUT: credFile },
	stdout: "inherit",
	stderr: "inherit",
});
if (setup.exitCode !== 0) process.exit(1);
const env = Object.fromEntries(
	readFileSync(credFile, "utf8").trim().split("\n").map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
);
const ts = new Coffer(env.COFFER_URL!, env.COFFER_CLIENT_ID!, env.COFFER_CLIENT_SECRET!);

const bin = (name: string, override?: string) => override || Bun.which(name);
type Lang = { id: string; tool: string | null; prepare: (dir: string) => void; cmd: (tool: string) => string[] };
const langs: Lang[] = [
	{
		id: "ts",
		tool: bin("node", process.env.NODE),
		prepare: (d) => ["coffer.ts", "test/run.ts"].forEach((f) => copyFileSync(join(SDK, f), join(d, f.replace("test/", "")))),
		cmd: (t) => [t, "run.ts", "ts"],
	},
	{
		id: "go",
		tool: bin("go", process.env.GO),
		prepare: (d) => {
			mkdirSync(join(d, "coffer"));
			copyFileSync(join(SDK, "coffer.go"), join(d, "coffer", "coffer.go"));
			copyFileSync(join(SDK, "test", "main.go"), join(d, "main.go"));
			writeFileSync(join(d, "go.mod"), "module cofferdemo\n\ngo 1.24\n");
		},
		cmd: (t) => [t, "run", ".", "go"],
	},
	{
		id: "dotnet",
		tool: bin("dotnet", process.env.DOTNET),
		prepare: (d) => ["Coffer.cs", "test/Program.cs", "test/CofferTest.csproj"].forEach((f) => copyFileSync(join(SDK, f), join(d, f.replace("test/", "")))),
		cmd: (t) => [t, "run", "--", "dotnet"],
	},
	{
		id: "php",
		tool: bin("php", process.env.PHP),
		prepare: (d) => ["Coffer.php", "test/run.php"].forEach((f) => copyFileSync(join(SDK, f), join(d, f.replace("test/", "")))),
		cmd: (t) => [t, "run.php", "php"],
	},
];

let failures = 0;
const skipped: string[] = [];
const written: string[] = [];
function check(cond: unknown, what: string) {
	console.log(`${cond ? "✓" : "✗"} ${what}`);
	if (!cond) failures++;
}
const expected = (lang: string) => `hello from ${lang} ünï ✓ "q"\n<&>`;

console.log("\n--- SDK matrix");
for (const l of langs) {
	if (!l.tool) {
		skipped.push(l.id);
		console.log(`• ${l.id}: toolchain not found, skipped`);
		continue;
	}
	const dir = join(work, l.id);
	mkdirSync(dir);
	l.prepare(dir);
	const p = Bun.spawnSync(l.cmd(l.tool), {
		cwd: dir,
		env: { ...process.env, ...env, GOTOOLCHAIN: "local", DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1" },
	});
	const out = p.stdout.toString().trim().split("\n").pop() ?? "";
	let r: any = null;
	try {
		r = JSON.parse(out);
	} catch {
		// reported below
	}
	if (p.exitCode !== 0 || !r) {
		check(false, `${l.id}: runs (exit ${p.exitCode}) ${p.stderr.toString().trim().slice(-800)} ${out.slice(-400)}`);
		continue;
	}
	check(r.got === expected(l.id) && r.version >= 1, `${l.id}: writeSecret + getSecret round trip`);
	check(r.missingFound === false, `${l.id}: missing secret → null/undefined`);
	check(r.deletedOnce === true && r.deletedTwice === false, `${l.id}: deleteSecret`);
	check(r.all?.DATABASE_URL === "postgres://dev2", `${l.id}: reads a secret written by the dashboard`);
	for (const prev of written) check(r.all?.[`FROM_${prev}`] === expected(prev), `${l.id}: reads what ${prev} wrote`);
	check((await ts.getSecret(`FROM_${l.id}`)) === expected(l.id), `ts reads what ${l.id} wrote`);
	written.push(l.id);
}

rmSync(work, { recursive: true, force: true });
console.log(`\n${failures ? `${failures} check(s) failed` : "all checks passed"}${skipped.length ? ` (skipped: ${skipped.join(", ")})` : ""}`);
process.exit(failures ? 1 : 0);
