import { TriangleAlert } from "lucide-preact";
import { useState } from "preact/hooks";
import { createVault } from "../lib/vault.ts";
import { MIN_PASSWORD_LENGTH, MIN_PIN_LENGTH, validatePassword, validatePin } from "../lib/vault-core.ts";
import { JoinForm, RecoverForm, RecoveryKeyView, SignInForm } from "./AccountForms.tsx";
import { AuthScreen, ErrorText, PinInput } from "./common.tsx";
import { Alert, Button, Checkbox, Field, Input } from "@cfsa/ui";

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
			<AuthScreen subtitle="Account created">
				<RecoveryKeyView recoveryKey={recoveryKey} onDone={onDone} />
			</AuthScreen>
		);
	}
	return (
		<AuthScreen subtitle={subtitle[mode]}>
			{mode === "create" && <CreateVault onDone={onDone} />}
			{mode === "signin" && <SignInForm onDone={onDone} />}
			{mode === "join" && <JoinForm invite={invite} createLocal onRecoveryKey={setRecoveryKey} />}
			{mode === "recover" && <RecoverForm onDone={onDone} />}
			<div class="flex flex-wrap justify-center gap-x-4 gap-y-1">
				{mode !== "create" && <Button variant="link" onClick={() => setMode("create")}>Use without an account</Button>}
				{mode !== "signin" && <Button variant="link" onClick={() => setMode("signin")}>Sign in to sync</Button>}
				{mode !== "join" && <Button variant="link" onClick={() => setMode("join")}>I have an invite link</Button>}
				{mode === "signin" && <Button variant="link" onClick={() => setMode("recover")}>Forgot password?</Button>}
			</div>
		</AuthScreen>
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
		<form class="grid gap-4" onSubmit={submit}>
			<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
			<Field label="Master password" htmlFor="pw" hint={`At least ${MIN_PASSWORD_LENGTH} characters. A long passphrase is best.`}>
				<Input id="pw" type="password" autocomplete="new-password" value={password}
					onInput={(e) => setPassword(e.currentTarget.value)} autofocus />
			</Field>
			<Field label="Confirm master password" htmlFor="pw2">
				<Input id="pw2" type="password" autocomplete="new-password" value={confirm}
					onInput={(e) => setConfirm(e.currentTarget.value)} />
			</Field>
			<Checkbox checked={usePin} onChange={(e) => setUsePin(e.currentTarget.checked)}>
				Also unlock with a PIN on this device
			</Checkbox>
			{usePin && (
				<>
					<Field label={`PIN (${MIN_PIN_LENGTH}+ digits)`} htmlFor="pin">
						<PinInput id="pin" value={pin} onValue={setPin} />
					</Field>
					<Field label="Confirm PIN" htmlFor="pin2">
						<PinInput id="pin2" value={pinConfirm} onValue={setPinConfirm} />
					</Field>
				</>
			)}
			<ErrorText>{error}</ErrorText>
			<Button type="submit" class="w-full" disabled={busy}>{busy ? "Creating vault…" : "Create vault"}</Button>
			<Alert variant="warning" icon={<TriangleAlert />} title="There is no password recovery for a local vault.">
				Save your master password in a password manager such as Bitwarden or Proton Pass. Codes are encrypted and
				stored only on this device.
			</Alert>
		</form>
	);
}
