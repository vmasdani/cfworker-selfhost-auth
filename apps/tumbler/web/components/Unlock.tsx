import { CircleCheck } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import { getAccount } from "../lib/account.ts";
import { PinError, unlockWithPassword, unlockWithPin } from "../lib/vault.ts";
import { RecoverForm } from "./AccountForms.tsx";
import { AuthScreen, ErrorText, PinInput } from "./common.tsx";
import { Alert, Button, Field, Input } from "./ui/index.tsx";

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
			<AuthScreen subtitle="Recover your account">
				<RecoverForm username={linkedUser} onDone={() => { setRecovering(false); setRecovered(true); setMode("password"); }} />
				<Button variant="link" onClick={() => setRecovering(false)}>Back</Button>
			</AuthScreen>
		);
	}

	return (
		<AuthScreen subtitle="Vault locked">
			<form class="grid gap-4" onSubmit={submit}>
				{recovered && <Alert variant="success" icon={<CircleCheck />}>Password changed. Unlock with your new password.</Alert>}
				<input type="text" name="username" autocomplete="username" value="Tumbler local vault" hidden readOnly />
				{pinMode ? (
					<Field label="PIN" htmlFor="unlock">
						<PinInput key="pin" id="unlock" value={value} onValue={setValue} autofocus />
					</Field>
				) : (
					<Field label="Master password" htmlFor="unlock">
						<Input id="unlock" key="pw" type="password" autocomplete="current-password" value={value}
							onInput={(e) => setValue(e.currentTarget.value)} autofocus />
					</Field>
				)}
				<ErrorText>{error}</ErrorText>
				<Button type="submit" class="w-full" disabled={busy || !value}>{busy ? "Unlocking…" : "Unlock"}</Button>
				<div class="flex flex-col items-center gap-1">
					{hasPin && (
						<Button variant="link" onClick={() => { setMode(pinMode ? "password" : "pin"); setValue(""); setError(null); }}>
							{pinMode ? "Use master password instead" : "Use PIN instead"}
						</Button>
					)}
					{linkedUser && !pinMode && (
						<Button variant="link" onClick={() => setRecovering(true)}>Forgot password? Use recovery key</Button>
					)}
				</div>
			</form>
		</AuthScreen>
	);
}
