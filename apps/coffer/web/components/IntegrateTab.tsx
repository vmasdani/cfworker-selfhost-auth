import { Alert, Button, Tabs } from "@cfsa/ui";
import { Download, Info } from "lucide-preact";
import { useState } from "preact/hooks";
import goSource from "../../sdk/coffer.go?raw";
import tsSource from "../../sdk/coffer.ts?raw";
import csSource from "../../sdk/Coffer.cs?raw";
import phpSource from "../../sdk/Coffer.php?raw";
import { CopyButton, download, Hint, Section } from "./common.tsx";

type Lang = "ts" | "go" | "cs" | "php";

interface Sdk {
	label: string;
	file: string;
	source: string;
	requires: string;
	usage: string;
}

const SDKS: Record<Lang, Sdk> = {
	ts: {
		label: "TypeScript / JS",
		file: "coffer.ts",
		source: tsSource,
		requires: "Node.js 20+, Bun, Deno, Cloudflare Workers or a browser. No packages. Node runs .ts directly (22.18+), or strip the types for plain JS.",
		usage: `import { Coffer } from "./coffer.ts";

// Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET (and COFFER_URL) from the environment.
// Node: node --env-file=.env app.ts · Bun loads .env itself · Workers: Coffer.fromEnv(env)
const coffer = Coffer.fromEnv();

const all = await coffer.listAllSecrets();
console.log(Object.keys(all));

const dbUrl = await coffer.getSecret("DATABASE_URL");
await coffer.writeSecret("LAST_DEPLOY", new Date().toISOString()); // read-write client IDs only`,
	},
	go: {
		label: "Go",
		file: "coffer.go",
		source: goSource,
		requires: "Go 1.24+ (crypto/hkdf). Standard library only. Put the file in a coffer/ package in your module.",
		usage: `import "yourmodule/coffer"

// Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET (and COFFER_URL) from the environment.
c, err := coffer.FromEnv()
if err != nil { log.Fatal(err) }

all, err := c.ListAllSecrets(ctx)
dbURL, ok, err := c.GetSecret(ctx, "DATABASE_URL")
_, err = c.WriteSecret(ctx, "LAST_DEPLOY", time.Now().Format(time.RFC3339)) // read-write only`,
	},
	cs: {
		label: "C# / .NET",
		file: "Coffer.cs",
		source: csSource,
		requires: ".NET 8+. Base class library only (HKDF, AesGcm, HttpClient, System.Text.Json). Add the file to your project.",
		usage: `using CofferSdk;

// Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET (and COFFER_URL) from the environment.
using var coffer = Coffer.FromEnv();

var all = await coffer.ListAllSecretsAsync();
string? dbUrl = await coffer.GetSecretAsync("DATABASE_URL");
await coffer.WriteSecretAsync("LAST_DEPLOY", DateTime.UtcNow.ToString("o")); // read-write only`,
	},
	php: {
		label: "PHP",
		file: "Coffer.php",
		source: phpSource,
		requires: "PHP 8.1+ with openssl, curl and json (on by default almost everywhere). No Composer packages.",
		usage: `require_once __DIR__ . '/Coffer.php';

// Reads COFFER_CLIENT_ID, COFFER_CLIENT_SECRET (and COFFER_URL) via getenv, $_ENV or $_SERVER,
// so Laravel/Symfony .env loading works as is.
$coffer = Coffer::fromEnv();

$all = $coffer->listAllSecrets();
$dbUrl = $coffer->getSecret('DATABASE_URL');
$coffer->writeSecret('LAST_DEPLOY', date(DATE_ATOM)); // read-write only`,
	},
};

const withUrl = (s: string) => s.replaceAll("__COFFER_URL__", location.origin);

export function IntegrateTab() {
	const [lang, setLang] = useState<Lang>("ts");
	const [showSource, setShowSource] = useState(false);
	const sdk = SDKS[lang];
	const source = withUrl(sdk.source);
	const env = `COFFER_URL=${location.origin}\nCOFFER_CLIENT_ID=cfi_...\nCOFFER_CLIENT_SECRET=cfs_...\n`;

	return (
		<div class="grid gap-6">
			<Alert icon={<Info />} title="One file, no dependencies, end-to-end encrypted">
				Copy the client file into your app and set the three variables below (create a client ID under Access). The file
				decrypts secrets on your server; Coffer only stores and serves ciphertext.
			</Alert>

			<Section title="1. Environment variables" description="Put these in your app's .env or secret store. The client secret is shown once, when you create the client ID.">
				<pre class="bg-muted break-anywhere rounded-lg px-4 py-3 font-mono text-xs whitespace-pre-wrap">{env}</pre>
				<div><CopyButton value={env} label="Copy template" secret={false} /></div>
			</Section>

			<Section title="2. Client file">
				<Tabs value={lang} onChange={(v) => { setLang(v); setShowSource(false); }} items={(Object.keys(SDKS) as Lang[]).map((k) => ({ value: k, label: SDKS[k].label }))} />
				<Hint>{sdk.requires}</Hint>
				<div class="flex flex-wrap gap-2">
					<Button onClick={() => download(sdk.file, source)}><Download /> Download {sdk.file}</Button>
					<CopyButton value={source} label={`Copy ${sdk.file}`} secret={false} size="default" />
					<Button variant="ghost" onClick={() => setShowSource(!showSource)}>{showSource ? "Hide source" : "View source"}</Button>
				</div>
				{showSource && (
					<pre class="bg-muted max-h-[32rem] overflow-auto rounded-lg px-4 py-3 font-mono text-xs leading-relaxed">{source}</pre>
				)}
			</Section>

			<Section title="3. Use it">
				<pre class="bg-muted overflow-auto rounded-lg px-4 py-3 font-mono text-xs leading-relaxed">{sdk.usage}</pre>
				<div><CopyButton value={sdk.usage} label="Copy example" secret={false} /></div>
			</Section>
		</div>
	);
}
