import { useState } from "preact/hooks";
import { createVault } from "../lib/vault.ts";
import { MIN_PASSWORD_LENGTH, MIN_PIN_LENGTH, validatePassword, validatePin } from "../lib/vault-core.ts";
import { JoinForm, RecoverForm, RecoveryKeyView, SignInForm } from "./AccountForms.tsx";
import { Brand, PinInput } from "./ui.tsx";

type Mode = "create" | "signin" | "join" | "recover";

export function Setup({ onDone, invite }: { onDone: () => void; invite?: string }) {
	const [mode, setMode] = useState<Mode>(invite ? "join" : "create");
	const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
	const subtitle: Record<Mode, string> = {
		create: "Create a local vault on this device",
		signin: "Sign in to your sync account",
		join: "Create your account from an invite",
		recover: "Recover your account",
	};
	if (recoveryKey) {
		return (
			<div class="centered">
				<div class="card">
					<Brand subtitle="Account created" />
					<RecoveryKeyView recoveryKey={recoveryKey} onDone={onDone} />
				</div>
			</div>
		);
	}
	return (
		<div class="centered">
			<div class="card">
				<Brand subtitle={subtitle[mode]} />
				{mode === "create" && <CreateVault onDone={onDone} />}
				{mode === "signin" && <SignInForm onDone={onDone} />}
				{mode === "join" && <JoinForm invite={invite} createLocal onRecoveryKey={setRecoveryKey} />}
				{mode === "recover" && <RecoverForm onDone={onDone} />}
				<div class="mode-links">
					{mode !== "create" && <button class="link" onClick={() => setMode("create")}>Use without an account</button>}
					{mode !== "signin" && <button class="link" onClick={() => setMode("signin")}>Sign in to sync</button>}
					{mode !== "join" && <button class="link" onClick={() => setMode("join")}>I have an invite link</button>}
					{mode === "signin" && <button class="link" onClick={() => setMode("recover")}>Forgot password?</button>}
				</div>
			</div>
		</div>
	);
}

function CreateVault({ onDone }: { onDone: () => void }) {
	const [password, setPassword] = useState("");
	const [confirm, setConfirm] = useState("");
	const [usePin, setUsePin] = useState(false);
	const [pin, setPin] = useState("");
	const [pinConfirm, setPinConfirm] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	async function submit(e: Event) {
		e.preventDefault();
		const err =
			validatePassword(password) ??
			(password !== confirm ? "Passwords do not match" : null) ??
			(usePin ? (validatePin(pin) ?? (pin !== pinConfirm ? "PINs do not match" : null)) : null);
		if (err) return setError(err);
		setError(null);
		setBusy(true);
		try {
			await createVault(password, usePin ? pin : undefined);
			onDone();
		} catch (e) {
			setError(e instanceof Error ? e.message : String(e));
		} finally {
			setBusy(false);
		}
	}

	return (
		<form onSubmit={submit}>
				<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />

				<label for="pw">Master password</label>
				<input id="pw" type="password" autocomplete="new-password" value={password}
					onInput={(e) => setPassword(e.currentTarget.value)} autofocus />
				<p class="hint">At least {MIN_PASSWORD_LENGTH} characters. A long passphrase is best.</p>

				<label for="pw2">Confirm master password</label>
				<input id="pw2" type="password" autocomplete="new-password" value={confirm}
					onInput={(e) => setConfirm(e.currentTarget.value)} />

				<label class="check">
					<input type="checkbox" checked={usePin} onChange={(e) => setUsePin(e.currentTarget.checked)} />
					Also unlock with a PIN on this device
				</label>
				{usePin && (
					<>
						<label for="pin">PIN ({MIN_PIN_LENGTH}+ digits)</label>
						<PinInput id="pin" value={pin} onValue={setPin} />
						<label for="pin2">Confirm PIN</label>
						<PinInput id="pin2" value={pinConfirm} onValue={setPinConfirm} />
					</>
				)}

				{error && <p class="error">{error}</p>}
				<button class="primary block" type="submit" disabled={busy}>
					{busy ? "Creating vault…" : "Create vault"}
				</button>

				<div class="notice warn">
					<strong>There is no password recovery for a local vault.</strong> Save your master password in a
					password manager such as Bitwarden or Proton Pass. Codes are encrypted and stored only on this device.
				</div>
			</form>
	);
}
