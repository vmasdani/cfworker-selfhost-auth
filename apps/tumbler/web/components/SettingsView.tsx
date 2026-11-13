import { Download, Lock, Upload } from "lucide-preact";
import { useState } from "preact/hooks";
import { changePassword } from "../lib/account.ts";
import { MIN_PIN_LENGTH, validatePassword, validatePin } from "../lib/vault-core.ts";
import { removePin, setPin, type Settings } from "../lib/vault.ts";
import { AccountSection } from "./AccountSection.tsx";
import { ErrorText, Hint, Page, PinInput, Section } from "./common.tsx";
import { Badge, Button, Field, Input, Select, Switch } from "./ui/index.tsx";

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
		<Page title="Settings" onBack={onBack}>
			<AccountSection invite={invite} onPinMaybeRemoved={() => void onPinChanged()} />

			<Section title="Display">
				<div class="flex items-center justify-between gap-4">
					<div class="grid gap-1">
						<label for="shownext" class="text-sm font-medium">Show next code</label>
						<Hint class="text-xs">Show the upcoming code under the current one, as Proton Authenticator does.</Hint>
					</div>
					<Switch id="shownext" label="Show next code" checked={settings.showNextCode}
						onChange={(v) => onSettings({ ...settings, showNextCode: v })} />
				</div>
			</Section>

			<Section title="Security">
				<Field label="Auto-lock after inactivity" htmlFor="autolock" hint="The vault also locks after 1 minute in the background.">
					<Select id="autolock" value={settings.autoLockMinutes}
						onChange={(e) => onSettings({ ...settings, autoLockMinutes: Number(e.currentTarget.value) })}>
						{AUTO_LOCK.map((m) => <option value={m}>{m} minute{m > 1 ? "s" : ""}</option>)}
					</Select>
				</Field>
				<Field label="Clear copied codes from clipboard" htmlFor="clip">
					<Select id="clip" value={settings.clipboardClearSeconds}
						onChange={(e) => onSettings({ ...settings, clipboardClearSeconds: Number(e.currentTarget.value) })}>
						{CLIPBOARD.map((s) => <option value={s}>{s === 0 ? "Never" : `After ${s} seconds`}</option>)}
					</Select>
				</Field>
				<Button variant="outline" class="w-full" onClick={onLock}><Lock /> Lock now</Button>
			</Section>

			<Section title="Import & export"
				description="Import from Proton Authenticator, Google Authenticator, otpauth:// lists or a Tumbler backup. Export an encrypted backup, or to Proton or Google Authenticator.">
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" onClick={onImport}><Upload /> Import</Button>
					<Button variant="outline" onClick={onExport}><Download /> Export</Button>
				</div>
			</Section>

			<PinSection hasPin={hasPin} onChanged={onPinChanged} />

			<PasswordSection />

			<Section title="About">
				<Hint>
					Tumbler Authenticator. Codes are encrypted with AES-256-GCM on this device. With sync, the server
					stores only ciphertext.
				</Hint>
			</Section>
		</Page>
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
		<Section title="PIN unlock">
			<div class="flex items-start justify-between gap-3">
				<Hint>
					{hasPin ? "PIN unlock is on." : "PIN unlock is off."} A PIN is quicker than your master password but weaker:
					use {MIN_PIN_LENGTH}+ random digits. After 5 wrong PINs, the master password is required.
				</Hint>
				<Badge variant={hasPin ? "default" : "secondary"}>{hasPin ? "On" : "Off"}</Badge>
			</div>
			{editing ? (
				<form class="grid gap-4" onSubmit={save}>
					<Field label="New PIN" htmlFor="newpin"><PinInput id="newpin" value={pin} onValue={setPinValue} autofocus /></Field>
					<Field label="Confirm PIN" htmlFor="newpin2"><PinInput id="newpin2" value={confirm} onValue={setConfirm} /></Field>
					<div class="grid grid-cols-2 gap-2">
						<Button variant="outline" onClick={() => setEditing(false)}>Cancel</Button>
						<Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save PIN"}</Button>
					</div>
				</form>
			) : (
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" class={hasPin ? "" : "col-span-2"} onClick={() => { setEditing(true); setMsg(null); }}>
						{hasPin ? "Change PIN" : "Set PIN"}
					</Button>
					{hasPin && <Button variant="destructive-outline" onClick={remove}>Remove PIN</Button>}
				</div>
			)}
			{msg && (msg.error ? <ErrorText>{msg.text}</ErrorText> : <Hint>{msg.text}</Hint>)}
		</Section>
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
		<Section title="Master password">
			<form class="grid gap-4" onSubmit={save}>
				<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
				<Field label="Current master password" htmlFor="cur">
					<Input id="cur" type="password" autocomplete="current-password" value={current} onInput={(e) => setCurrent(e.currentTarget.value)} />
				</Field>
				<Field label="New master password" htmlFor="next">
					<Input id="next" type="password" autocomplete="new-password" value={next} onInput={(e) => setNext(e.currentTarget.value)} />
				</Field>
				<Field label="Confirm new master password" htmlFor="next2">
					<Input id="next2" type="password" autocomplete="new-password" value={confirm} onInput={(e) => setConfirm(e.currentTarget.value)} />
				</Field>
				<Button type="submit" class="w-full" disabled={busy || !current || !next}>{busy ? "Changing…" : "Change master password"}</Button>
				{msg && (msg.error ? <ErrorText>{msg.text}</ErrorText> : <Hint>{msg.text}</Hint>)}
			</form>
		</Section>
	);
}
