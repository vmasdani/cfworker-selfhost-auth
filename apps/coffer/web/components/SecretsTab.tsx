import { Button, Card, Field, Input, Select, Tabs, Textarea } from "@cfsa/ui";
import { Download, Eye, EyeOff, FileUp, History, KeyRound, Pencil, Plus, Search, Trash2, X } from "lucide-preact";
import { useEffect, useMemo, useState } from "preact/hooks";
import { formatDotenv, parseDotenv } from "../lib/dotenv.ts";
import {
	deleteSecret,
	listSecrets,
	putSecret,
	SECRET_NAME,
	secretHistory,
	type Environment,
	type HistoryItem,
	type Project,
	type Secret,
} from "../lib/projects.ts";
import { CopyButton, download, EmptyState, ErrorText, errorMessage, Hint, timeAgo, toast } from "./common.tsx";

type Panel = { kind: "add" } | { kind: "edit"; secret: Secret } | { kind: "import" } | null;

export function EnvPicker({ project, envId, onChange }: { project: Project; envId: string; onChange: (id: string) => void }) {
	if (project.environments.length <= 5) {
		return <Tabs value={envId} onChange={onChange} items={project.environments.map((e) => ({ value: e.id, label: e.name }))} />;
	}
	return (
		<Select aria-label="Environment" value={envId} onChange={(e) => onChange(e.currentTarget.value)}>
			{project.environments.map((e) => <option value={e.id}>{e.name}</option>)}
		</Select>
	);
}

export function SecretsTab({ project, envId, setEnvId, onChanged }: {
	project: Project;
	envId: string;
	setEnvId: (id: string) => void;
	onChanged: () => void;
}) {
	const env = project.environments.find((e) => e.id === envId) ?? project.environments[0]!;
	const [secrets, setSecrets] = useState<Secret[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [query, setQuery] = useState("");
	const [panel, setPanel] = useState<Panel>(null);
	const [revealed, setRevealed] = useState<Set<string>>(new Set());
	const [historyOf, setHistoryOf] = useState<string | null>(null);

	async function load() {
		try {
			setSecrets(await listSecrets(env));
			setError(null);
		} catch (e) {
			setError(errorMessage(e));
		}
	}

	useEffect(() => {
		setSecrets(null);
		setPanel(null);
		setRevealed(new Set());
		setHistoryOf(null);
		void load();
	}, [env.id]);

	const shown = useMemo(() => {
		const q = query.trim().toLowerCase();
		return (secrets ?? []).filter((s) => !q || s.name.toLowerCase().includes(q));
	}, [secrets, query]);

	const changed = async () => {
		await load();
		onChanged();
	};

	async function remove(s: Secret) {
		if (!confirm(`Delete ${s.name} from ${env.name}? Apps using it will stop getting it. The old value stays in history.`)) return;
		try {
			await deleteSecret(env, s.name);
			toast(`Deleted ${s.name}`);
			await changed();
		} catch (e) {
			setError(errorMessage(e));
		}
	}

	const toggle = (mac: string) => setRevealed((r) => {
		const n = new Set(r);
		if (n.has(mac)) n.delete(mac);
		else n.add(mac);
		return n;
	});

	return (
		<div class="grid gap-4">
			<EnvPicker project={project} envId={env.id} onChange={setEnvId} />

			<div class="flex flex-wrap items-center gap-2">
				<div class="relative min-w-48 flex-1">
					<Search class="text-muted-foreground pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
					<Input aria-label="Search secrets" placeholder="Search" class="pl-9" value={query} onInput={(e) => setQuery(e.currentTarget.value)} />
				</div>
				<Button onClick={() => setPanel({ kind: "add" })}><Plus /> Add secret</Button>
				<Button variant="outline" onClick={() => setPanel({ kind: "import" })}><FileUp /> Import .env</Button>
				<Button variant="outline" disabled={!secrets?.length}
					onClick={() => {
						if (!confirm(`Download ${env.name} as a plaintext .env file? Anyone with the file can read these secrets.`)) return;
						download(`${project.name}.${env.name}.env`.replace(/[^A-Za-z0-9._-]+/g, "-"), formatDotenv(secrets!.map((s) => [s.name, s.value])));
					}}>
					<Download /> Export .env
				</Button>
			</div>

			{panel?.kind === "add" && <SecretForm env={env} existing={secrets ?? []} onClose={() => setPanel(null)} onSaved={changed} />}
			{panel?.kind === "edit" && <SecretForm env={env} existing={secrets ?? []} secret={panel.secret} onClose={() => setPanel(null)} onSaved={changed} />}
			{panel?.kind === "import" && <ImportDotenv env={env} existing={secrets ?? []} onClose={() => setPanel(null)} onSaved={changed} />}

			<ErrorText>{error}</ErrorText>

			{secrets === null ? (
				<Hint>Decrypting…</Hint>
			) : secrets.length === 0 ? (
				<EmptyState icon={<KeyRound />} title={`No secrets in ${env.name}`}>Add one, or import a .env file.</EmptyState>
			) : (
				<Card class="gap-0 py-0">
					<ul class="divide-y">
						{shown.map((s) => (
							<li key={s.mac} class="grid gap-2 px-4 py-3">
								<div class="flex flex-wrap items-center gap-x-3 gap-y-1">
									<code class="break-anywhere min-w-0 basis-full font-mono text-sm font-medium sm:flex-1 sm:basis-0">{s.name}</code>
									<span class="text-muted-foreground flex-1 text-xs sm:flex-none">v{s.version} · {timeAgo(s.updatedAt)}</span>
									<div class="flex items-center">
										<Button variant="ghost" size="icon" aria-label={revealed.has(s.mac) ? `Hide ${s.name}` : `Reveal ${s.name}`} onClick={() => toggle(s.mac)}>
											{revealed.has(s.mac) ? <EyeOff /> : <Eye />}
										</Button>
										<CopyButton value={s.value} label={`Copy ${s.name}`} size="icon" variant="ghost" />
										<Button variant="ghost" size="icon" aria-label={`Edit ${s.name}`} onClick={() => setPanel({ kind: "edit", secret: s })}><Pencil /></Button>
										<Button variant="ghost" size="icon" aria-label={`History of ${s.name}`} onClick={() => setHistoryOf(historyOf === s.mac ? null : s.mac)}><History /></Button>
										<Button variant="ghost" size="icon" aria-label={`Delete ${s.name}`} class="text-destructive" onClick={() => remove(s)}><Trash2 /></Button>
									</div>
								</div>
								<pre class="bg-muted/60 text-muted-foreground break-anywhere max-h-48 overflow-auto rounded-md px-3 py-2 font-mono text-xs whitespace-pre-wrap">
									{revealed.has(s.mac) ? (s.value || "(empty)") : "•".repeat(Math.min(24, Math.max(8, s.value.length)))}
								</pre>
								{historyOf === s.mac && <HistoryPanel env={env} secret={s} onRestored={changed} />}
							</li>
						))}
					</ul>
					{shown.length === 0 && <p class="text-muted-foreground px-4 py-6 text-center text-sm">No secret matches “{query}”.</p>}
				</Card>
			)}
		</div>
	);
}

function SecretForm({ env, existing, secret, onClose, onSaved }: {
	env: Environment;
	existing: Secret[];
	secret?: Secret;
	onClose: () => void;
	onSaved: () => Promise<void>;
}) {
	const [name, setName] = useState(secret?.name ?? "");
	const [value, setValue] = useState(secret?.value ?? "");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		const n = name.trim();
		if (!SECRET_NAME.test(n)) return setError("Name: start with a letter or _, then letters, digits, _ . or - (max 128)");
		if (!secret && existing.some((s) => s.name === n) && !confirm(`${n} already exists in ${env.name}. Replace its value?`)) return;
		setBusy(true);
		setError(null);
		try {
			await putSecret(env, n, value);
			toast(`Saved ${n} in ${env.name}`);
			await onSaved();
			onClose();
		} catch (err) {
			setError(errorMessage(err));
			setBusy(false);
		}
	}

	return (
		<Card class="px-5">
			<form class="grid gap-4" onSubmit={submit}>
				<div class="flex items-center justify-between">
					<h3 class="font-semibold">{secret ? `Edit ${secret.name}` : `Add secret to ${env.name}`}</h3>
					<Button variant="ghost" size="icon" aria-label="Close" onClick={onClose}><X /></Button>
				</div>
				<Field label="Name" htmlFor="sf-name">
					<Input id="sf-name" class="font-mono" value={name} readOnly={!!secret} autofocus={!secret} spellcheck={false} autocapitalize="characters"
						placeholder="DATABASE_URL" onInput={(e) => setName(e.currentTarget.value)} />
				</Field>
				<Field label="Value" htmlFor="sf-value" hint="Encrypted in this browser before it is sent.">
					<Textarea id="sf-value" value={value} autofocus={!!secret} spellcheck={false} autocomplete="off" onInput={(e) => setValue(e.currentTarget.value)} />
				</Field>
				<ErrorText>{error}</ErrorText>
				<div class="flex justify-end gap-2">
					<Button variant="outline" onClick={onClose}>Cancel</Button>
					<Button type="submit" disabled={busy || !name}>{busy ? "Encrypting…" : "Save"}</Button>
				</div>
			</form>
		</Card>
	);
}

function ImportDotenv({ env, existing, onClose, onSaved }: { env: Environment; existing: Secret[]; onClose: () => void; onSaved: () => Promise<void> }) {
	const [text, setText] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const parsed = useMemo(() => parseDotenv(text), [text]);
	const valid = parsed.entries.filter(([k]) => SECRET_NAME.test(k));
	const replacing = valid.filter(([k]) => existing.some((s) => s.name === k)).length;

	async function submit(e: Event) {
		e.preventDefault();
		if (replacing && !confirm(`Replace ${replacing} existing secret(s) in ${env.name}?`)) return;
		setBusy(true);
		setError(null);
		try {
			for (const [k, v] of valid) await putSecret(env, k, v);
			toast(`Imported ${valid.length} secret(s) into ${env.name}`);
			await onSaved();
			onClose();
		} catch (err) {
			setError(errorMessage(err));
			setBusy(false);
		}
	}

	return (
		<Card class="px-5">
			<form class="grid gap-4" onSubmit={submit}>
				<div class="flex items-center justify-between">
					<h3 class="font-semibold">Import .env into {env.name}</h3>
					<Button variant="ghost" size="icon" aria-label="Close" onClick={onClose}><X /></Button>
				</div>
				<Field label="Paste a .env file" htmlFor="imp-text" hint="KEY=value per line. Comments, quotes and export are understood.">
					<Textarea id="imp-text" class="min-h-40" value={text} spellcheck={false} autocomplete="off" placeholder={"DATABASE_URL=postgres://…\nAPI_TOKEN=\"…\""}
						onInput={(e) => setText(e.currentTarget.value)} />
				</Field>
				<label class="text-sm">
					<span class="text-muted-foreground">or choose a file: </span>
					<input type="file" accept=".env,text/plain" class="text-sm" onChange={async (e) => {
						const f = e.currentTarget.files?.[0];
						if (f) setText(await f.text());
						e.currentTarget.value = "";
					}} />
				</label>
				{text && (
					<Hint>
						{valid.length} secret(s) found{replacing ? `, ${replacing} will replace existing values` : ""}.
						{parsed.errors.length > 0 && ` Skipped: ${parsed.errors.join("; ")}.`}
					</Hint>
				)}
				<ErrorText>{error}</ErrorText>
				<div class="flex justify-end gap-2">
					<Button variant="outline" onClick={onClose}>Cancel</Button>
					<Button type="submit" disabled={busy || !valid.length}>{busy ? "Encrypting…" : `Import ${valid.length || ""}`}</Button>
				</div>
			</form>
		</Card>
	);
}

function HistoryPanel({ env, secret, onRestored }: { env: Environment; secret: Secret; onRestored: () => Promise<void> }) {
	const [items, setItems] = useState<HistoryItem[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [show, setShow] = useState<number | null>(null);

	useEffect(() => {
		secretHistory(env, secret.mac).then(setItems, (e) => setError(errorMessage(e)));
	}, [secret.mac, secret.version]);

	if (error) return <ErrorText>{error}</ErrorText>;
	if (!items) return <Hint class="text-xs">Loading history…</Hint>;
	if (!items.length) return <Hint class="text-xs">No previous versions.</Hint>;
	return (
		<div class="grid gap-2 rounded-md border px-3 py-2">
			<p class="text-xs font-medium">Previous versions</p>
			{items.map((h, i) => (
				<div key={i} class="grid gap-1">
					<div class="flex flex-wrap items-center gap-2 text-xs">
						<span class="font-medium">v{h.version}</span>
						<span class="text-muted-foreground">
							{new Date(h.updatedAt).toLocaleString()} by {h.updatedBy}
							{h.deleted ? " · deleted" : ""}
						</span>
						<div class="flex-1" />
						<Button variant="ghost" size="sm" onClick={() => setShow(show === i ? null : i)}>{show === i ? "Hide" : "Show"}</Button>
						<Button variant="ghost" size="sm" onClick={async () => {
							if (!confirm(`Restore v${h.version} of ${secret.name}?`)) return;
							await putSecret(env, secret.name, h.value);
							toast(`Restored ${secret.name}`);
							await onRestored();
						}}>Restore</Button>
					</div>
					{show === i && <pre class="bg-muted/60 break-anywhere rounded px-2 py-1 font-mono text-xs whitespace-pre-wrap">{h.value || "(empty)"}</pre>}
				</div>
			))}
		</div>
	);
}
