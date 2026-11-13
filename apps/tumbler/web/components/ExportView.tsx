import { encodeGoogleMigration, formatProtonExport, formatUriList, type GoogleExport } from "@cfsa/importers";
import { ChevronLeft, ChevronRight, Download, QrCode as QrCodeIcon, ShieldCheck, TriangleAlert } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import { createBackup, downloadFile, today } from "../lib/backup.ts";
import type { Entry } from "../lib/entries.ts";
import { MIN_PASSWORD_LENGTH, validatePassword } from "../lib/vault-core.ts";
import { listEntries, verifyMasterPassword } from "../lib/vault.ts";
import { ErrorText, Hint, Page } from "./common.tsx";
import { QrCode } from "./QrCode.tsx";
import { Alert, Button, Card, Checkbox, Field, Input, Select } from "./ui/index.tsx";

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
		<Page title="Export" onBack={onDone}>
			<Card class="px-5">
				<Hint>{entries.length} account{entries.length === 1 ? "" : "s"} in this vault.</Hint>
				<Field label="Format" htmlFor="fmt">
					<Select id="fmt" value={format} onChange={(e) => setFormat(e.currentTarget.value as Format)}>
						<option value="backup">Encrypted backup (recommended)</option>
						<option value="proton">Proton Authenticator · unencrypted</option>
						<option value="google">Google Authenticator QR · unencrypted</option>
						<option value="uri">otpauth:// list · unencrypted</option>
					</Select>
				</Field>
				{format === "backup" ? <BackupExport entries={entries} /> : <PlainExport format={format} entries={entries} />}
			</Card>
		</Page>
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
		<Page title="Export" onBack={onCancel}>
			<form onSubmit={submit}>
				<Card class="px-5">
					<Hint>Exports contain your 2FA secrets. Enter your master password to continue.</Hint>
					<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
					<Field label="Master password" htmlFor="mpw">
						<Input id="mpw" type="password" autocomplete="current-password" value={pw} autofocus
							onInput={(e) => setPw(e.currentTarget.value)} />
					</Field>
					<ErrorText>{error}</ErrorText>
					<Button type="submit" class="w-full" disabled={busy || !pw}>{busy ? "Checking…" : "Continue"}</Button>
				</Card>
			</form>
		</Page>
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
		<form class="grid gap-4" onSubmit={submit}>
			<Alert icon={<ShieldCheck />}>
				Encrypted with a backup password (AES-256-GCM). Restore it on any device with Import → File.
				You can reuse your master password or choose a different one ({MIN_PASSWORD_LENGTH}+ characters).
			</Alert>
			<Field label="Backup password" htmlFor="bpw">
				<Input id="bpw" type="password" autocomplete="new-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} />
			</Field>
			<Field label="Confirm backup password" htmlFor="bpw2">
				<Input id="bpw2" type="password" autocomplete="new-password" value={confirm} onInput={(e) => setConfirm(e.currentTarget.value)} />
			</Field>
			{msg && (msg.error ? <ErrorText>{msg.text}</ErrorText> : <Hint>{msg.text}</Hint>)}
			<Button type="submit" class="w-full" disabled={busy || !pw || entries.length === 0}>
				<Download /> {busy ? "Encrypting…" : "Download encrypted backup"}
			</Button>
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
			<div class="grid gap-4">
				{google.skipped.length > 0 && (
					<Alert variant="warning" icon={<TriangleAlert />}
						title={`${google.skipped.length} account(s) not included (Google Authenticator only supports 6 or 8 digits and 30 s):`}>
						<ul>{google.skipped.map((s) => <li>{s.entry.issuer || s.entry.account}: {s.reason}</li>)}</ul>
					</Alert>
				)}
				{uri ? (
					<>
						<Hint>In Google Authenticator: Transfer accounts → Import accounts, then scan QR code {page + 1} of {google.uris.length}.</Hint>
						<QrCode value={uri} label={`Google Authenticator transfer code ${page + 1} of ${google.uris.length}`} />
						{google.uris.length > 1 && (
							<div class="grid grid-cols-2 gap-2">
								<Button variant="outline" disabled={page === 0} onClick={() => setPage(page - 1)}><ChevronLeft /> Previous</Button>
								<Button disabled={page >= google.uris.length - 1} onClick={() => setPage(page + 1)}>Next <ChevronRight /></Button>
							</div>
						)}
					</>
				) : (
					<Hint>Nothing to export.</Hint>
				)}
				<Button variant="outline" class="w-full" onClick={() => setGoogle(null)}>Hide QR codes</Button>
			</div>
		);
	}

	return (
		<div class="grid gap-4">
			<Alert variant="warning" icon={<TriangleAlert />} title="This export is not encrypted.">
				Anyone who gets the {format === "google" ? "QR codes" : "file"} can generate your 2FA codes.{" "}
				{format === "google" ? "Make sure no one can see your screen." : "Delete the file once you have imported it elsewhere."}
			</Alert>
			<Checkbox checked={ack} onChange={(e) => setAck(e.currentTarget.checked)}>I understand</Checkbox>
			<Button class="w-full" disabled={!ack || entries.length === 0} onClick={go}>
				{format === "google" ? <><QrCodeIcon /> Show QR codes</> : <><Download /> Download</>}
			</Button>
		</div>
	);
}
