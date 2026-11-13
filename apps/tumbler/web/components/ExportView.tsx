import { encodeGoogleMigration, formatProtonExport, formatUriList, type GoogleExport } from "@cfsa/importers";
import { useEffect, useState } from "preact/hooks";
import { createBackup, downloadFile, today } from "../lib/backup.ts";
import type { Entry } from "../lib/entries.ts";
import { MIN_PASSWORD_LENGTH, validatePassword } from "../lib/vault-core.ts";
import { listEntries, verifyMasterPassword } from "../lib/vault.ts";
import { QrCode } from "./QrCode.tsx";
import { TopBar } from "./ui.tsx";

type Format = "backup" | "proton" | "uri" | "google";

export function ExportView({ onDone }: { onDone: () => void }) {
	const [verified, setVerified] = useState(false);
	const [entries, setEntries] = useState<Entry[]>([]);
	const [format, setFormat] = useState<Format>("backup");

	useEffect(() => {
		if (verified) void listEntries().then(setEntries);
	}, [verified]);

	if (!verified) return <ConfirmPassword onOk={() => setVerified(true)} onCancel={onDone} />;

	return (
		<div class="shell">
			<TopBar title="Export" onBack={onDone} />
			<p class="hint">{entries.length} account{entries.length === 1 ? "" : "s"} in this vault.</p>
			<label for="fmt">Format</label>
			<select id="fmt" value={format} onChange={(e) => setFormat(e.currentTarget.value as Format)}>
				<option value="backup">Encrypted backup (recommended)</option>
				<option value="proton">Proton Authenticator · unencrypted</option>
				<option value="google">Google Authenticator QR · unencrypted</option>
				<option value="uri">otpauth:// list · unencrypted</option>
			</select>
			{format === "backup" ? <BackupExport entries={entries} /> : <PlainExport format={format} entries={entries} />}
		</div>
	);
}

function ConfirmPassword({ onOk, onCancel }: { onOk: () => void; onCancel: () => void }) {
	const [pw, setPw] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	async function submit(e: Event) {
		e.preventDefault();
		setBusy(true);
		setError(null);
		if (await verifyMasterPassword(pw)) onOk();
		else {
			setError("Wrong master password");
			setBusy(false);
		}
	}
	return (
		<div class="shell">
			<TopBar title="Export" onBack={onCancel} />
			<form onSubmit={submit}>
				<p class="hint">Exports contain your 2FA secrets. Enter your master password to continue.</p>
				<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
				<label for="mpw">Master password</label>
				<input id="mpw" type="password" autocomplete="current-password" value={pw} autofocus
					onInput={(e) => setPw(e.currentTarget.value)} />
				{error && <p class="error">{error}</p>}
				<button class="primary block" type="submit" disabled={busy || !pw}>{busy ? "Checking…" : "Continue"}</button>
			</form>
		</div>
	);
}

function BackupExport({ entries }: { entries: Entry[] }) {
	const [pw, setPw] = useState("");
	const [confirm, setConfirm] = useState("");
	const [busy, setBusy] = useState(false);
	const [msg, setMsg] = useState<{ error: boolean; text: string } | null>(null);
	async function submit(e: Event) {
		e.preventDefault();
		const err = validatePassword(pw) ?? (pw !== confirm ? "Passwords do not match" : null);
		if (err) return setMsg({ error: true, text: err });
		setBusy(true);
		try {
			downloadFile(`tumbler-backup-${today()}.json`, await createBackup(entries, pw), "application/json");
			setMsg({ error: false, text: "Backup downloaded. Store it somewhere safe, away from this device." });
			setPw("");
			setConfirm("");
		} catch (e) {
			setMsg({ error: true, text: e instanceof Error ? e.message : String(e) });
		} finally {
			setBusy(false);
		}
	}
	return (
		<form onSubmit={submit}>
			<p class="hint">
				Encrypted with a backup password (AES-256-GCM). Restore it on any device with Import → File.
				You can reuse your master password or choose a different one ({MIN_PASSWORD_LENGTH}+ characters).
			</p>
			<label for="bpw">Backup password</label>
			<input id="bpw" type="password" autocomplete="new-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
			<label for="bpw2">Confirm backup password</label>
			<input id="bpw2" type="password" autocomplete="new-password" value={confirm} onInput={(e) => setConfirm(e.currentTarget.value)} />
			{msg && <p class={msg.error ? "error" : "hint"}>{msg.text}</p>}
			<button class="primary block" type="submit" disabled={busy || !pw || entries.length === 0}>
				{busy ? "Encrypting…" : "Download encrypted backup"}
			</button>
		</form>
	);
}

function PlainExport({ format, entries }: { format: Exclude<Format, "backup">; entries: Entry[] }) {
	const [ack, setAck] = useState(false);
	const [google, setGoogle] = useState<GoogleExport | null>(null);
	const [page, setPage] = useState(0);

	useEffect(() => { setAck(false); setGoogle(null); setPage(0); }, [format]);

	function go() {
		if (format === "proton") downloadFile(`tumbler-export-proton-${today()}.json`, formatProtonExport(entries), "application/json");
		else if (format === "uri") downloadFile(`tumbler-export-otpauth-${today()}.txt`, formatUriList(entries), "text/plain");
		else setGoogle(encodeGoogleMigration(entries));
	}

	if (google) {
		const uri = google.uris[page];
		return (
			<div>
				{google.skipped.length > 0 && (
					<div class="notice warn">
						{google.skipped.length} account(s) not included (Google Authenticator only supports 6 or 8 digits and 30 s):
						<ul>{google.skipped.map((s) => <li>{s.entry.issuer || s.entry.account}: {s.reason}</li>)}</ul>
					</div>
				)}
				{uri ? (
					<>
						<p class="hint">In Google Authenticator: Transfer accounts → Import accounts, then scan QR code {page + 1} of {google.uris.length}.</p>
						<QrCode value={uri} label={`Google Authenticator transfer code ${page + 1} of ${google.uris.length}`} />
						{google.uris.length > 1 && <div class="actions">
							<button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
							<button type="button" class="primary" disabled={page >= google.uris.length - 1} onClick={() => setPage(page + 1)}>Next</button>
						</div>}
					</>
				) : (
					<p class="hint">Nothing to export.</p>
				)}
				<button type="button" class="block" onClick={() => setGoogle(null)}>Hide QR codes</button>
			</div>
		);
	}

	return (
		<div>
			<div class="notice warn">
				<strong>This export is not encrypted.</strong> Anyone who gets the {format === "google" ? "QR codes" : "file"} can
				generate your 2FA codes. {format === "google" ? "Make sure no one can see your screen." : "Delete the file once you have imported it elsewhere."}
			</div>
			<label class="check">
				<input type="checkbox" checked={ack} onChange={(e) => setAck(e.currentTarget.checked)} />
				I understand
			</label>
			<button class="primary block" type="button" disabled={!ack || entries.length === 0} onClick={go}>
				{format === "google" ? "Show QR codes" : "Download"}
			</button>
		</div>
	);
}
