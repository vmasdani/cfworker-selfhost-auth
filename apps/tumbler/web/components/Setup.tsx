import { useState } from "preact/hooks";
import { createVault } from "../lib/vault.ts";
import { MIN_PASSWORD_LENGTH, MIN_PIN_LENGTH, validatePassword, validatePin } from "../lib/vault-core.ts";
import { Brand } from "./ui.tsx";

export function Setup({ onDone }: { onDone: () => void }) {
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
		<div class="centered">
			<form class="card" onSubmit={submit}>
				<Brand subtitle="Create a local vault on this device" />
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
						<input id="pin" type="password" inputMode="numeric" autocomplete="off" value={pin}
							onInput={(e) => setPin(e.currentTarget.value.replace(/\D/g, ""))} />
						<label for="pin2">Confirm PIN</label>
						<input id="pin2" type="password" inputMode="numeric" autocomplete="off" value={pinConfirm}
							onInput={(e) => setPinConfirm(e.currentTarget.value.replace(/\D/g, ""))} />
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
		</div>
	);
}
