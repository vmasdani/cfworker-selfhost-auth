import { useState } from "preact/hooks";
import { MIN_PIN_LENGTH, validatePassword, validatePin } from "../lib/vault-core.ts";
import { changePassword } from "../lib/account.ts";
import { removePin, setPin, type Settings } from "../lib/vault.ts";
import { AccountSection } from "./AccountSection.tsx";
import { TopBar } from "./ui.tsx";

interface Props {
	settings: Settings;
	hasPin: boolean;
	onSettings: (s: Settings) => Promise<void>;
	onPinChanged: () => Promise<unknown>;
	onLock: () => void;
	onImport: () => void;
	onExport: () => void;
	onBack: () => void;
	invite?: string;
}

const AUTO_LOCK = [1, 2, 5, 15, 30, 60];
const CLIPBOARD = [0, 15, 30, 60, 120];

export function SettingsView({ settings, hasPin, onSettings, onPinChanged, onLock, onImport, onExport, onBack, invite }: Props) {
	return (
		<div class="shell">
			<TopBar title="Settings" onBack={onBack} />

			<h2>Sync</h2>
			<AccountSection invite={invite} onPinMaybeRemoved={() => void onPinChanged()} />

			<h2>Security</h2>
			<div class="settings-group">
				<label for="autolock">Auto-lock after inactivity</label>
				<select id="autolock" value={settings.autoLockMinutes}
					onChange={(e) => onSettings({ ...settings, autoLockMinutes: Number(e.currentTarget.value) })}>
					{AUTO_LOCK.map((m) => <option value={m}>{m} minute{m > 1 ? "s" : ""}</option>)}
				</select>
				<p class="hint">The vault also locks after 1 minute in the background.</p>

				<label for="clip">Clear copied codes from clipboard</label>
				<select id="clip" value={settings.clipboardClearSeconds}
					onChange={(e) => onSettings({ ...settings, clipboardClearSeconds: Number(e.currentTarget.value) })}>
					{CLIPBOARD.map((s) => <option value={s}>{s === 0 ? "Never" : `After ${s} seconds`}</option>)}
				</select>
				<div class="actions"><button onClick={onLock}>Lock now</button></div>
			</div>

			<h2>Import &amp; export</h2>
			<div class="settings-group">
				<p class="hint">
					Import from Proton Authenticator, Google Authenticator, otpauth:// lists or a Tumbler backup.
					Export an encrypted backup, or to Proton or Google Authenticator.
				</p>
				<div class="actions">
					<button onClick={onImport}>Import</button>
					<button onClick={onExport}>Export</button>
				</div>
			</div>

			<h2>PIN unlock</h2>
			<PinSection hasPin={hasPin} onChanged={onPinChanged} />

			<h2>Master password</h2>
			<PasswordSection />

			<h2>About</h2>
			<div class="settings-group">
				<p class="hint">
					Tumbler Authenticator. Codes are encrypted with AES-256-GCM on this device. With sync, the server
					stores only ciphertext.
				</p>
			</div>
		</div>
	);
}

function PinSection({ hasPin, onChanged }: { hasPin: boolean; onChanged: () => Promise<unknown> }) {
	const [editing, setEditing] = useState(false);
	const [pin, setPinValue] = useState("");
	const [confirm, setConfirm] = useState("");
	const [msg, setMsg] = useState<{ error: boolean; text: string } | null>(null);
	const [busy, setBusy] = useState(false);

	async function save(e: Event) {
		e.preventDefault();
		const err = validatePin(pin) ?? (pin !== confirm ? "PINs do not match" : null);
		if (err) return setMsg({ error: true, text: err });
		setBusy(true);
		try {
			await setPin(pin);
			await onChanged();
			setEditing(false);
			setPinValue("");
			setConfirm("");
			setMsg({ error: false, text: "PIN saved." });
		} catch (e) {
			setMsg({ error: true, text: e instanceof Error ? e.message : String(e) });
		} finally {
			setBusy(false);
		}
	}

	async function remove() {
		await removePin();
		await onChanged();
		setMsg({ error: false, text: "PIN removed." });
	}

	return (
		<div class="settings-group">
			<p class="hint">
				{hasPin ? "PIN unlock is on." : "PIN unlock is off."} A PIN is quicker than your master password but weaker:
				use {MIN_PIN_LENGTH}+ random digits. After 5 wrong PINs, the master password is required.
			</p>
			{editing ? (
				<form onSubmit={save}>
					<label for="newpin">New PIN</label>
					<input id="newpin" type="password" inputMode="numeric" autocomplete="off" value={pin}
						onInput={(e) => setPinValue(e.currentTarget.value.replace(/\D/g, ""))} autofocus />
					<label for="newpin2">Confirm PIN</label>
					<input id="newpin2" type="password" inputMode="numeric" autocomplete="off" value={confirm}
						onInput={(e) => setConfirm(e.currentTarget.value.replace(/\D/g, ""))} />
					<div class="actions">
						<button type="button" onClick={() => setEditing(false)}>Cancel</button>
						<button class="primary" type="submit" disabled={busy}>{busy ? "Saving…" : "Save PIN"}</button>
					</div>
				</form>
			) : (
				<div class="actions">
					<button onClick={() => { setEditing(true); setMsg(null); }}>{hasPin ? "Change PIN" : "Set PIN"}</button>
					{hasPin && <button class="danger" onClick={remove}>Remove PIN</button>}
				</div>
			)}
			{msg && <p class={msg.error ? "error" : "hint"}>{msg.text}</p>}
		</div>
	);
}

function PasswordSection() {
	const [current, setCurrent] = useState("");
	const [next, setNext] = useState("");
	const [confirm, setConfirm] = useState("");
	const [msg, setMsg] = useState<{ error: boolean; text: string } | null>(null);
	const [busy, setBusy] = useState(false);

	async function save(e: Event) {
		e.preventDefault();
		const err = validatePassword(next) ?? (next !== confirm ? "Passwords do not match" : null);
		if (err) return setMsg({ error: true, text: err });
		setBusy(true);
		try {
			await changePassword(current, next);
			setCurrent("");
			setNext("");
			setConfirm("");
			setMsg({ error: false, text: "Password changed. Update it in your password manager." });
		} catch (e) {
			setMsg({ error: true, text: e instanceof Error ? e.message : String(e) });
		} finally {
			setBusy(false);
		}
	}

	return (
		<form class="settings-group" onSubmit={save}>
			<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
			<label for="cur">Current master password</label>
			<input id="cur" type="password" autocomplete="current-password" value={current}
				onInput={(e) => setCurrent(e.currentTarget.value)} />
			<label for="next">New master password</label>
			<input id="next" type="password" autocomplete="new-password" value={next}
				onInput={(e) => setNext(e.currentTarget.value)} />
			<label for="next2">Confirm new master password</label>
			<input id="next2" type="password" autocomplete="new-password" value={confirm}
				onInput={(e) => setConfirm(e.currentTarget.value)} />
			<div class="actions">
				<button class="primary" type="submit" disabled={busy || !current || !next}>
					{busy ? "Changing…" : "Change master password"}
				</button>
			</div>
			{msg && <p class={msg.error ? "error" : "hint"}>{msg.text}</p>}
		</form>
	);
}
