import {
	entryIdentity,
	ImportError,
	isGoogleMigrationUri,
	parseGoogleMigrationUri,
	parseImport,
	type ImportedEntry,
} from "@cfsa/importers";
import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { BackupPasswordError, isTumblerBackup, openBackup, type TumblerBackup } from "../lib/backup.ts";
import { importEntries, listEntries } from "../lib/vault.ts";
import { QrScanner } from "./QrScanner.tsx";
import { ErrorText, Hint, Page } from "./common.tsx";
import { Alert, Badge, Button, buttonClass, Card, Field, Input, Tabs, Textarea } from "./ui/index.tsx";
import { CircleCheck, ClipboardPaste, FileUp, QrCode as QrCodeIcon, ScanLine, TriangleAlert } from "lucide-preact";

interface Props {
	/** A Google migration URI scanned elsewhere, to start with. */
	initialUri?: string;
	onDone: () => void;
}

type Source = "proton" | "google-migration" | "otpauth-uri-list" | "tumbler-backup";

const SOURCE_LABEL: Record<Source, string> = {
	proton: "Proton Authenticator export",
	"google-migration": "Google Authenticator transfer",
	"otpauth-uri-list": "otpauth:// URI list",
	"tumbler-backup": "Tumbler backup",
};

interface Batch {
	id: number;
	index: number;
	size: number;
	entries: ImportedEntry[];
	warnings: string[];
}

interface Preview {
	source: Source;
	entries: ImportedEntry[];
	warnings: string[];
	plaintextFile: boolean;
}

export function ImportView({ initialUri, onDone }: Props) {
	const [mode, setMode] = useState<"file" | "google" | "paste">(initialUri ? "google" : "file");
	const [preview, setPreview] = useState<Preview | null>(null);
	const [pendingBackup, setPendingBackup] = useState<TumblerBackup | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [paste, setPaste] = useState("");
	// Google transfer batches scanned so far, keyed by batch index.
	const batchesRef = useRef(new Map<number, Batch>());
	const batches = batchesRef.current;
	const [, rerender] = useState(0);

	useEffect(() => {
		if (initialUri) addMigration(initialUri);
	}, []);

	function fail(e: unknown) {
		setError(e instanceof ImportError || e instanceof BackupPasswordError ? e.message : `Could not read: ${e instanceof Error ? e.message : e}`);
	}

	function fromText(text: string, plaintextFile: boolean) {
		setError(null);
		try {
			const t = text.trim();
			if (t.startsWith("{")) {
				const json = JSON.parse(t);
				if (isTumblerBackup(json)) return setPendingBackup(json);
			}
			const r = parseImport(t);
			setPreview({ source: r.format, entries: r.entries, warnings: r.warnings, plaintextFile });
		} catch (e) {
			fail(e instanceof SyntaxError ? new ImportError("File is not valid JSON") : e);
		}
	}

	async function onFile(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		input.value = "";
		if (!file) return;
		if (file.size > 5_000_000) return setError("File is too large");
		fromText(await file.text(), true);
	}

	function addMigration(value: string): boolean {
		if (!isGoogleMigrationUri(value)) {
			setError("That QR code is not a Google Authenticator transfer code. Use Add account for single codes.");
			return false;
		}
		try {
			const r = parseGoogleMigrationUri(value);
			setError(null);
			const m = batchesRef.current;
			// A code from a different export session starts over.
			if ([...m.values()][0]?.id !== undefined && [...m.values()][0]!.id !== r.batch.id) m.clear();
			m.set(r.batch.index, { ...r.batch, entries: r.entries, warnings: r.warnings });
			rerender((n) => n + 1);
			return m.size >= r.batch.size;
		} catch (e) {
			fail(e);
			return false;
		}
	}

	function finishGoogle() {
		const all = [...batches.values()].sort((a, b) => a.index - b.index);
		setPreview({
			source: "google-migration",
			entries: all.flatMap((b) => b.entries),
			warnings: all.flatMap((b) => b.warnings),
			plaintextFile: false,
		});
	}

	if (preview) return <ImportPreview preview={preview} onBack={() => setPreview(null)} onDone={onDone} />;
	if (pendingBackup) {
		return (
			<BackupPassword
				backup={pendingBackup}
				onCancel={() => setPendingBackup(null)}
				onOpened={(entries) => {
					setPendingBackup(null);
					setPreview({ source: "tumbler-backup", entries, warnings: [], plaintextFile: false });
				}}
			/>
		);
	}

	const expected = [...batches.values()][0]?.size ?? 0;

	return (
		<Page title="Import" onBack={onDone}>
			<div class="grid gap-4">
				<Tabs
					value={mode}
					onChange={(m) => { setMode(m); setError(null); }}
					items={[
						{ value: "file", label: <><FileUp /> File</> },
						{ value: "google", label: <><QrCodeIcon /> Google QR</> },
						{ value: "paste", label: <><ClipboardPaste /> Paste</> },
					]}
				/>

				{mode === "file" && (
					<Card class="px-5">
						<Hint>
							Supported: Proton Authenticator export (.json, without password), Tumbler backup (.json),
							and text files with one otpauth:// or otpauth-migration:// URI per line.
						</Hint>
						<label class={buttonClass("default", "default", "w-full")}>
							<FileUp /> Choose file
							<input type="file" accept=".json,.txt,application/json,text/plain" hidden onChange={onFile} />
						</label>
					</Card>
				)}

				{mode === "google" && (
					<Card class="px-5">
						<Hint>
							In Google Authenticator: menu → Transfer accounts → Export accounts. Scan each QR code it shows,
							or upload screenshots of them.
						</Hint>
						<QrScanner onResult={addMigration} />
						{expected > 0 && (
							<Alert variant="success" icon={<ScanLine />} title={
								<>Scanned {batches.size} of {expected} QR code{expected > 1 ? "s" : ""}{" · "}
									{[...batches.values()].reduce((n, b) => n + b.entries.length, 0)} accounts</>
							}>
								<div class="mt-1 grid grid-cols-2 gap-2">
									<Button variant="outline" onClick={() => { batchesRef.current.clear(); rerender((n) => n + 1); }}>Start over</Button>
									<Button onClick={finishGoogle}>
										{batches.size >= expected ? "Review accounts" : "Review scanned so far"}
									</Button>
								</div>
							</Alert>
						)}
					</Card>
				)}

				{mode === "paste" && (
					<Card class="px-5">
						<Field label="otpauth:// or otpauth-migration:// URIs, one per line" htmlFor="paste">
							<Textarea id="paste" value={paste} spellcheck={false} autocomplete="off"
								onInput={(e) => setPaste(e.currentTarget.value)} />
						</Field>
						<Button class="w-full" disabled={!paste.trim()} onClick={() => fromText(paste, false)}>Read</Button>
					</Card>
				)}

				<ErrorText>{error}</ErrorText>
			</div>
		</Page>
	);
}

function BackupPassword({ backup, onCancel, onOpened }: {
	backup: TumblerBackup;
	onCancel: () => void;
	onOpened: (e: ImportedEntry[]) => void;
}) {
	const [pw, setPw] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	async function submit(e: Event) {
		e.preventDefault();
		setBusy(true);
		setError(null);
		try {
			onOpened(await openBackup(backup, pw));
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			setBusy(false);
		}
	}
	return (
		<Page title="Open backup" onBack={onCancel}>
			<form onSubmit={submit}>
				<Card class="px-5">
					<Hint>Backup created {new Date(backup.createdAt).toLocaleString()}.</Hint>
					<Field label="Backup password" htmlFor="bpw">
						<Input id="bpw" type="password" autocomplete="off" value={pw} autofocus onInput={(e) => setPw(e.currentTarget.value)} />
					</Field>
					<ErrorText>{error}</ErrorText>
					<Button type="submit" class="w-full" disabled={busy || !pw}>{busy ? "Decrypting…" : "Decrypt"}</Button>
				</Card>
			</form>
		</Page>
	);
}

function ImportPreview({ preview, onBack, onDone }: { preview: Preview; onBack: () => void; onDone: () => void }) {
	const [existing, setExisting] = useState<Set<string> | null>(null);
	const [selected, setSelected] = useState<Set<number>>(new Set());
	const [busy, setBusy] = useState(false);
	const [done, setDone] = useState<number | null>(null);

	// Duplicate = already in the vault, or repeated earlier in this import.
	const dupes = useMemo(() => {
		if (!existing) return new Set<number>();
		const seen = new Set(existing);
		const d = new Set<number>();
		preview.entries.forEach((e, i) => {
			const id = entryIdentity(e);
			if (seen.has(id)) d.add(i);
			seen.add(id);
		});
		return d;
	}, [existing, preview]);

	useEffect(() => {
		void listEntries().then((list) => setExisting(new Set(list.map(entryIdentity))));
	}, []);
	useEffect(() => {
		setSelected(new Set(preview.entries.map((_, i) => i).filter((i) => !dupes.has(i))));
	}, [dupes]);

	const toggle = (i: number) => setSelected((s) => {
		const n = new Set(s);
		if (n.has(i)) n.delete(i);
		else n.add(i);
		return n;
	});

	async function doImport() {
		setBusy(true);
		const n = await importEntries(preview.entries.filter((_, i) => selected.has(i)));
		setDone(n);
		setBusy(false);
	}

	if (done !== null) {
		return (
			<Page title="Import">
				<div class="grid gap-4">
					<Alert variant="success" icon={<CircleCheck />} title={`Imported ${done} account${done === 1 ? "" : "s"}.`} />
					{preview.plaintextFile && preview.source !== "tumbler-backup" && (
						<Alert variant="warning" icon={<TriangleAlert />} title="Delete the export file now.">
							It contains your 2FA secrets in plain text.
						</Alert>
					)}
					<Button class="w-full" onClick={onDone}>Done</Button>
				</div>
			</Page>
		);
	}

	return (
		<Page title="Review import" onBack={onBack}>
			<div class="grid gap-4">
				<Hint>
					{SOURCE_LABEL[preview.source]} · {preview.entries.length} account{preview.entries.length === 1 ? "" : "s"}
					{dupes.size > 0 && ` · ${dupes.size} already in your vault (unchecked)`}
				</Hint>
				{preview.warnings.length > 0 && (
					<Alert variant="warning" icon={<TriangleAlert />} title={`${preview.warnings.length} item(s) skipped`}>
						<ul>{preview.warnings.map((w) => <li>{w}</li>)}</ul>
					</Alert>
				)}
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" onClick={() => setSelected(new Set(preview.entries.map((_, i) => i)))}>Select all</Button>
					<Button variant="outline" onClick={() => setSelected(new Set())}>Select none</Button>
				</div>
				<ul class="import-list bg-card divide-y rounded-xl border">
					{preview.entries.map((e, i) => (
						<li>
							<label class="flex cursor-pointer items-center gap-3 px-4 py-3">
								<input type="checkbox" class="size-4 shrink-0 accent-primary" checked={selected.has(i)} onChange={() => toggle(i)} />
								<span class="grid min-w-0 flex-1">
									<span class="truncate text-sm font-medium">{e.issuer || e.account || "Unnamed"}</span>
									{e.issuer && e.account && <span class="text-muted-foreground truncate text-xs">{e.account}</span>}
								</span>
								{dupes.has(i) && <Badge variant="warning">duplicate</Badge>}
								{e.type === "hotp" && <Badge>HOTP</Badge>}
							</label>
						</li>
					))}
				</ul>
				<Button class="w-full" disabled={busy || selected.size === 0 || !existing} onClick={doImport}>
					{busy ? "Importing…" : `Import ${selected.size} account${selected.size === 1 ? "" : "s"}`}
				</Button>
			</div>
		</Page>
	);
}
