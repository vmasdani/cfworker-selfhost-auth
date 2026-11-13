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
import { TopBar } from "./ui.tsx";

interface Props {
	/** Present when editing. */
	entry?: Entry;
	onDone: () => void;
}

type Draft = Omit<OtpParams, "digits" | "period" | "counter"> & { digits: string; period: string; counter: string; note: string };

function toDraft(p?: Partial<Entry>): Draft {
	const d = { ...DEFAULT_OTP, issuer: "", account: "", secret: "", note: "", ...p };
	return { ...d, digits: String(d.digits), period: String(d.period), counter: String(d.counter) };
}

export function EntryForm({ entry, onDone }: Props) {
	const editing = !!entry;
	const [tab, setTab] = useState<"manual" | "uri">("manual");
	const [draft, setDraft] = useState<Draft>(toDraft(entry));
	const [uri, setUri] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft((d) => ({ ...d, [k]: v }));

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
		<div class="shell">
			<TopBar title={editing ? "Edit account" : "Add account"} onBack={onDone} />
			{!editing && (
				<div class="tabs" role="tablist">
					<button type="button" class={tab === "manual" ? "active" : ""} onClick={() => setTab("manual")}>Enter key</button>
					<button type="button" class={tab === "uri" ? "active" : ""} onClick={() => setTab("uri")}>Paste otpauth:// URI</button>
				</div>
			)}

			{tab === "uri" && !editing ? (
				<div>
					<label for="uri">otpauth:// URI</label>
					<textarea id="uri" value={uri} placeholder="otpauth://totp/Issuer:account?secret=…" autocomplete="off"
						spellcheck={false} onInput={(e) => setUri(e.currentTarget.value)} />
					{error && <p class="error">{error}</p>}
					<button class="primary block" type="button" onClick={applyUri} disabled={!uri.trim()}>Read URI</button>
					<p class="hint">QR scanning and importing from Google Authenticator or Proton Authenticator are coming next.</p>
				</div>
			) : (
				<form onSubmit={save}>
					<label for="issuer">Issuer</label>
					<input id="issuer" value={draft.issuer} placeholder="e.g. GitHub" autocomplete="off"
						onInput={(e) => set("issuer", e.currentTarget.value)} />
					<label for="account">Account</label>
					<input id="account" value={draft.account} placeholder="e.g. you@example.com" autocomplete="off"
						onInput={(e) => set("account", e.currentTarget.value)} />
					{!editing && (
						<>
							<label for="secret">Secret key</label>
							<input id="secret" value={draft.secret} placeholder="Base32, e.g. JBSW Y3DP EHPK 3PXP"
								autocomplete="off" spellcheck={false} autocapitalize="characters"
								onInput={(e) => set("secret", e.currentTarget.value)} />
						</>
					)}
					<label for="note">Note</label>
					<input id="note" value={draft.note} placeholder="Optional" autocomplete="off"
						onInput={(e) => set("note", e.currentTarget.value)} />

					<details>
						<summary>Advanced</summary>
						<div class="row">
							<div>
								<label for="type">Type</label>
								<select id="type" value={draft.type} disabled={editing}
									onChange={(e) => set("type", e.currentTarget.value as OtpType)}>
									<option value="totp">Time-based (TOTP)</option>
									<option value="hotp">Counter-based (HOTP)</option>
								</select>
							</div>
							<div>
								<label for="alg">Algorithm</label>
								<select id="alg" value={draft.algorithm} disabled={editing}
									onChange={(e) => set("algorithm", e.currentTarget.value as OtpAlgorithm)}>
									<option>SHA1</option>
									<option>SHA256</option>
									<option>SHA512</option>
								</select>
							</div>
							<div>
								<label for="digits">Digits</label>
								<input id="digits" type="number" min={4} max={10} value={draft.digits} disabled={editing}
									onInput={(e) => set("digits", e.currentTarget.value)} />
							</div>
							{draft.type === "totp" ? (
								<div>
									<label for="period">Period (s)</label>
									<input id="period" type="number" min={1} max={3600} value={draft.period} disabled={editing}
										onInput={(e) => set("period", e.currentTarget.value)} />
								</div>
							) : (
								<div>
									<label for="counter">Counter</label>
									<input id="counter" type="number" min={0} value={draft.counter}
										onInput={(e) => set("counter", e.currentTarget.value)} />
								</div>
							)}
						</div>
					</details>

					{error && <p class="error">{error}</p>}
					<button class="primary block" type="submit" disabled={busy}>{editing ? "Save" : "Add account"}</button>
					{editing && <button class="danger block" type="button" onClick={remove}>Delete account</button>}
				</form>
			)}
		</div>
	);
}
