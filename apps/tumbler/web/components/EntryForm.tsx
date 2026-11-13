import {
	DEFAULT_OTP,
	OtpauthError,
	parseOtpauthUri,
	validateOtpParams,
	type OtpAlgorithm,
	type OtpParams,
	type OtpType,
} from "@cfsa/totp";
import { useState } from "preact/hooks";
import type { Entry } from "../lib/entries.ts";
import { deleteEntry, newEntryId, saveEntries } from "../lib/vault.ts";
import { QrScanner } from "./QrScanner.tsx";
import { ErrorText, Page } from "./common.tsx";
import { Button, Card, Field, Input, Select, Tabs, Textarea } from "./ui/index.tsx";
import { ChevronRight, KeyRound, Link2, ScanLine, Trash2 } from "lucide-preact";

interface Props {
	/** Present when editing. */
	entry?: Entry;
	onDone: () => void;
	/** A Google Authenticator transfer QR was scanned: hand it to the import flow. */
	onImportMigration?: (uri: string) => void;
}

type Draft = Omit<OtpParams, "digits" | "period" | "counter"> & { digits: string; period: string; counter: string; note: string };

function toDraft(p?: Partial<Entry>): Draft {
	const d = { ...DEFAULT_OTP, issuer: "", account: "", secret: "", note: "", ...p };
	return { ...d, digits: String(d.digits), period: String(d.period), counter: String(d.counter) };
}

export function EntryForm({ entry, onDone, onImportMigration }: Props) {
	const editing = !!entry;
	const [tab, setTab] = useState<"scan" | "manual" | "uri">(entry ? "manual" : "scan");
	const [draft, setDraft] = useState<Draft>(toDraft(entry));
	const [uri, setUri] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));

	function onScan(value: string): boolean {
		if (/^otpauth-migration:/i.test(value)) {
			onImportMigration?.(value);
			return true;
		}
		try {
			const p = parseOtpauthUri(value);
			setDraft(toDraft({ ...p, note: draft.note }));
			setError(null);
			setTab("manual");
			return true;
		} catch (e) {
			setError(e instanceof OtpauthError ? `QR code: ${e.message}` : "This QR code is not a 2FA setup code");
			return false;
		}
	}

	function applyUri() {
		try {
			const p = parseOtpauthUri(uri);
			setDraft(toDraft({ ...p, note: draft.note }));
			setError(null);
			setUri("");
			setTab("manual");
		} catch (e) {
			setError(e instanceof OtpauthError ? e.message : "Could not read URI");
		}
	}

	async function save(e: Event) {
		e.preventDefault();
		let params: OtpParams;
		try {
			params = validateOtpParams({
				type: draft.type,
				issuer: draft.issuer,
				account: draft.account,
				secret: draft.secret,
				algorithm: draft.algorithm,
				digits: Number(draft.digits),
				period: Number(draft.period),
				counter: Number(draft.counter),
			});
		} catch (err) {
			return setError(err instanceof Error ? err.message : String(err));
		}
		if (!params.issuer && !params.account) return setError("Enter an issuer or account name");
		setBusy(true);
		try {
			const now = Date.now();
			await saveEntries([
				{
					...params,
					id: entry?.id ?? newEntryId(),
					note: draft.note.trim(),
					createdAt: entry?.createdAt ?? now,
					updatedAt: now,
				},
			]);
			onDone();
		} catch (err) {
			setError(err instanceof Error ? err.message : String(err));
			setBusy(false);
		}
	}

	async function remove() {
		if (!entry) return;
		const name = entry.issuer || entry.account;
		if (!confirm(`Delete "${name}"?\n\nMake sure 2FA is disabled on that account or you have another way to sign in.`)) return;
		await deleteEntry(entry.id);
		onDone();
	}

	return (
		<Page title={editing ? "Edit account" : "Add account"} onBack={onDone}>
			<div class="grid gap-4">
				{!editing && (
					<Tabs
						value={tab}
						onChange={(t) => { setTab(t); setError(null); }}
						items={[
							{ value: "scan", label: <><ScanLine /> Scan QR</> },
							{ value: "manual", label: <><KeyRound /> Enter key</> },
							{ value: "uri", label: <><Link2 /> Paste URI</> },
						]}
					/>
				)}

				{tab === "scan" && !editing ? (
					<Card class="px-5">
						<QrScanner onResult={onScan}
							hint="Scan the 2FA setup QR code shown by the website, or a Google Authenticator transfer code." />
						<ErrorText>{error}</ErrorText>
					</Card>
				) : tab === "uri" && !editing ? (
					<Card class="px-5">
						<Field label="otpauth:// URI" htmlFor="uri">
							<Textarea id="uri" value={uri} placeholder="otpauth://totp/Issuer:account?secret=…" autocomplete="off"
								spellcheck={false} onInput={(e) => setUri(e.currentTarget.value)} />
						</Field>
						<ErrorText>{error}</ErrorText>
						<Button class="w-full" onClick={applyUri} disabled={!uri.trim()}>Read URI</Button>
					</Card>
				) : (
					<form onSubmit={save}>
						<Card class="px-5">
							<Field label="Issuer" htmlFor="issuer">
								<Input id="issuer" value={draft.issuer} placeholder="e.g. GitHub" autocomplete="off"
									onInput={(e) => set("issuer", e.currentTarget.value)} />
							</Field>
							<Field label="Account" htmlFor="account">
								<Input id="account" value={draft.account} placeholder="e.g. you@example.com" autocomplete="off"
									onInput={(e) => set("account", e.currentTarget.value)} />
							</Field>
							{!editing && (
								<Field label="Secret key" htmlFor="secret">
									<Input id="secret" class="font-mono" value={draft.secret} placeholder="Base32, e.g. JBSW Y3DP EHPK 3PXP"
										autocomplete="off" spellcheck={false} autocapitalize="characters"
										onInput={(e) => set("secret", e.currentTarget.value)} />
								</Field>
							)}
							<Field label="Note" htmlFor="note">
								<Input id="note" value={draft.note} placeholder="Optional" autocomplete="off"
									onInput={(e) => set("note", e.currentTarget.value)} />
							</Field>

							<details class="group">
								<summary class="text-muted-foreground hover:text-foreground flex cursor-pointer list-none items-center gap-1 text-sm">
									<ChevronRight class="size-4 transition-transform group-open:rotate-90" /> Advanced
								</summary>
								<div class="mt-4 grid grid-cols-2 gap-4">
									<Field label="Type" htmlFor="type">
										<Select id="type" value={draft.type} disabled={editing}
											onChange={(e) => set("type", e.currentTarget.value as OtpType)}>
											<option value="totp">Time-based (TOTP)</option>
											<option value="hotp">Counter-based (HOTP)</option>
										</Select>
									</Field>
									<Field label="Algorithm" htmlFor="alg">
										<Select id="alg" value={draft.algorithm} disabled={editing}
											onChange={(e) => set("algorithm", e.currentTarget.value as OtpAlgorithm)}>
											<option>SHA1</option>
											<option>SHA256</option>
											<option>SHA512</option>
										</Select>
									</Field>
									<Field label="Digits" htmlFor="digits">
										<Input id="digits" type="number" min={4} max={10} value={draft.digits} disabled={editing}
											onInput={(e) => set("digits", e.currentTarget.value)} />
									</Field>
									{draft.type === "totp" ? (
										<Field label="Period (s)" htmlFor="period">
											<Input id="period" type="number" min={1} max={3600} value={draft.period} disabled={editing}
												onInput={(e) => set("period", e.currentTarget.value)} />
										</Field>
									) : (
										<Field label="Counter" htmlFor="counter">
											<Input id="counter" type="number" min={0} value={draft.counter}
												onInput={(e) => set("counter", e.currentTarget.value)} />
										</Field>
									)}
								</div>
							</details>

							<ErrorText>{error}</ErrorText>
							<Button type="submit" class="w-full" disabled={busy}>{editing ? "Save" : "Add account"}</Button>
							{editing && (
								<Button variant="destructive-outline" class="w-full" onClick={remove}><Trash2 /> Delete account</Button>
							)}
						</Card>
					</form>
				)}
			</div>
		</Page>
	);
}
