// Test runner for coffer.ts (Node.js type stripping); see scripts/sdk-matrix.ts.
import { Coffer } from "./coffer.ts";

const lang = process.argv[2]!;
const c = Coffer.fromEnv();
const version = await c.writeSecret(`FROM_${lang}`, `hello from ${lang} ünï ✓ "q"\n<&>`);
const got = await c.getSecret(`FROM_${lang}`);
const missing = await c.getSecret("NOPE_MISSING");
await c.writeSecret(`TMP_${lang}`, "x");
const deletedOnce = await c.deleteSecret(`TMP_${lang}`);
const deletedTwice = await c.deleteSecret(`TMP_${lang}`);
console.log(JSON.stringify({ version, got, missingFound: missing !== undefined, deletedOnce, deletedTwice, all: await c.listAllSecrets() }));
