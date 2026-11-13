import { useEffect, useState } from "preact/hooks";
import { PinError, unlockWithPassword, unlockWithPin } from "../lib/vault.ts";
import { getAccount } from "../lib/account.ts";
import { RecoverForm } from "./AccountForms.tsx";
import { Brand, PinInput } from "./ui.tsx";

interface Props {
	hasPin: boolean;
	onUnlocked: () => void;
	onPinStateChange: () => Promise<unknown>;
}

export function Unlock({ hasPin, onUnlocked, onPinStateChange }: Props) {
	const [mode, setMode] = useState<"pin" | "password">(hasPin ? "pin" : "password");
	const [value, setValue] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const pinMode = mode === "pin" && hasPin;
	const [linkedUser, setLinkedUser] = useState<string | null>(null);
	const [recovering, setRecovering] = useState(false);
	const [recovered, setRecovered] = useState(false);
	useEffect(() => { void getAccount().then((a) => setLinkedUser(a?.username ?? null)); }, []);

	async function submit(e: Event) {
		e.preventDefault();
		if (!value) return;
		setBusy(true);
		setError(null);
		try {
			if (pinMode) await unlockWithPin(value);
			else await unlockWithPassword(value);
			setValue("");
			onUnlocked();
		} catch (err) {
			setValue("");
			setError(err instanceof Error ? err.message : String(err));
			if (err instanceof PinError) {
				await onPinStateChange();
				if (err.remaining === 0) setMode("password");
			}
		} finally {
			setBusy(false);
		}
	}

	if (recovering && linkedUser) {
		return (
			<div class="centered">
				<div class="card">
					<Brand subtitle="Recover your account" />
					<RecoverForm username={linkedUser} onDone={() => { setRecovering(false); setRecovered(true); setMode("password"); }} />
					<button class="link" onClick={() => setRecovering(false)}>Back</button>
				</div>
			</div>
		);
	}

	return (
		<div class="centered">
			<form class="card" onSubmit={submit}>
				<Brand subtitle="Vault locked" />
				{recovered && <div class="notice">Password changed. Unlock with your new password.</div>}
				<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
				{pinMode ? (
					<>
						<label for="unlock">PIN</label>
						<PinInput key="pin" id="unlock" value={value} onValue={setValue} autofocus />
					</>
				) : (
					<>
						<label for="unlock">Master password</label>
						<input id="unlock" key="pw" type="password" autocomplete="current-password" value={value}
							onInput={(e) => setValue(e.currentTarget.value)} autofocus />
					</>
				)}
				{error && <p class="error">{error}</p>}
				<button class="primary block" type="submit" disabled={busy || !value}>
					{busy ? "Unlocking…" : "Unlock"}
				</button>
				{hasPin && (
					<button type="button" class="link" onClick={() => { setMode(pinMode ? "password" : "pin"); setValue(""); setError(null); }}>
						{pinMode ? "Use master password instead" : "Use PIN instead"}
					</button>
				)}
				{linkedUser && !pinMode && (
					<button type="button" class="link" onClick={() => setRecovering(true)}>Forgot password? Use recovery key</button>
				)}
			</form>
		</div>
	);
}
