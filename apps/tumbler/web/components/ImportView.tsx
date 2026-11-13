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
import { TopBar } from "./ui.tsx";

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
		<div class="shell">
			<TopBar title="Import" onBack={onDone} />
			<div class="tabs" role="tablist">
				<button type="button" class={mode === "file" ? "active" : ""} onClick={() => setMode("file")}>File</button>
				<button type="button" class={mode === "google" ? "active" : ""} onClick={() => setMode("google")}>Google QR</button>
				<button type="button" class={mode === "paste" ? "active" : ""} onClick={() => setMode("paste")}>Paste</button>
			</div>

			{mode === "file" && (
				<div>
					<p class="hint">
						Supported: Proton Authenticator export (.json, without password), Tumbler backup (.json),
						and text files with one otpauth:// or otpauth-migration:// URI per line.
					</p>
					<label class="button primary block">
						Choose file
						<input type="file" accept=".json,.txt,application/json,text/plain" hidden onChange={onFile} />
					</label>
				</div>
			)}

			{mode === "google" && (
				<div>
					<p class="hint">
						In Google Authenticator: menu → Transfer accounts → Export accounts. Scan each QR code it shows,
						or upload screenshots of them.
					</p>
					<QrScanner onResult={addMigration} />
					{expected > 0 && (
						<div class="notice">
							Scanned {batches.size} of {expected} QR code{expected > 1 ? "s" : ""}
							{" · "}
							{[...batches.values()].reduce((n, b) => n + b.entries.length, 0)} accounts
							<div class="actions">
								<button type="button" onClick={() => { batchesRef.current.clear(); rerender((n) => n + 1); }}>Start over</button>
								<button type="button" class="primary" onClick={finishGoogle}>
									{batches.size >= expected ? "Review accounts" : "Review scanned so far"}
								</button>
							</div>
						</div>
					)}
				</div>
			)}

			{mode === "paste" && (
				<div>
					<label for="paste">otpauth:// or otpauth-migration:// URIs, one per line</label>
					<textarea id="paste" value={paste} spellcheck={false} autocomplete="off"
						onInput={(e) => setPaste(e.currentTarget.value)} />
					<button type="button" class="primary block" disabled={!paste.trim()} onClick={() => fromText(paste, false)}>
						Read
					</button>
				</div>
			)}

			{error && <p class="error">{error}</p>}
		</div>
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
		<div class="shell">
			<TopBar title="Open backup" onBack={onCancel} />
			<form onSubmit={submit}>
				<p class="hint">Backup created {new Date(backup.createdAt).toLocaleString()}.</p>
				<label for="bpw">Backup password</label>
				<input id="bpw" type="password" autocomplete="off" value={pw} autofocus onInput={(e) => setPw(e.currentTarget.value)} />
				{error && <p class="error">{error}</p>}
				<button class="primary block" type="submit" disabled={busy || !pw}>{busy ? "Decrypting…" : "Decrypt"}</button>
			</form>
		</div>
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
			<div class="shell">
				<TopBar title="Import" />
				<div class="notice">Imported {done} account{done === 1 ? "" : "s"}.</div>
				{preview.plaintextFile && preview.source !== "tumbler-backup" && (
					<div class="notice warn">
						<strong>Delete the export file now.</strong> It contains your 2FA secrets in plain text.
					</div>
				)}
				<button class="primary block" onClick={onDone}>Done</button>
			</div>
		);
	}

	return (
		<div class="shell">
			<TopBar title="Review import" onBack={onBack} />
			<p class="hint">
				{SOURCE_LABEL[preview.source]} · {preview.entries.length} account{preview.entries.length === 1 ? "" : "s"}
				{dupes.size > 0 && ` · ${dupes.size} already in your vault (unchecked)`}
			</p>
			{preview.warnings.length > 0 && (
				<div class="notice warn">
					<strong>{preview.warnings.length} item(s) skipped</strong>
					<ul>{preview.warnings.map((w) => <li>{w}</li>)}</ul>
				</div>
			)}
			<div class="actions">
				<button type="button" onClick={() => setSelected(new Set(preview.entries.map((_, i) => i)))}>Select all</button>
				<button type="button" onClick={() => setSelected(new Set())}>Select none</button>
			</div>
			<ul class="import-list">
				{preview.entries.map((e, i) => (
					<li>
						<label class="check">
							<input type="checkbox" checked={selected.has(i)} onChange={() => toggle(i)} />
							<span class="meta">
								<span class="issuer">{e.issuer || e.account || "Unnamed"}</span>
								{e.issuer && e.account && <span class="account">{e.account}</span>}
							</span>
							{dupes.has(i) && <span class="badge">duplicate</span>}
							{e.type === "hotp" && <span class="badge">HOTP</span>}
						</label>
					</li>
				))}
			</ul>
			<button class="primary block" disabled={busy || selected.size === 0 || !existing} onClick={doImport}>
				{busy ? "Importing…" : `Import ${selected.size} account${selected.size === 1 ? "" : "s"}`}
			</button>
		</div>
	);
}
