import { Alert, Button, Checkbox, Input, Label, Tabs } from "@cfsa/ui";
import { TriangleAlert } from "lucide-preact";
import { useState } from "preact/hooks";
import type { AccountResponse } from "../lib/api.ts";
import {
	joinWithInvite,
	MIN_PASSWORD_LENGTH,
	recoverAccount,
	signIn,
	signOut,
	TotpRequiredError,
	unlock,
	validatePassword,
} from "../lib/session.ts";
import { AuthScreen, CopyButton, ErrorText, errorMessage, Hint } from "./common.tsx";

/** Extract the token from a pasted invite link or a bare token. */
export function parseInvite(input: string): string {
	const s = input.trim();
	const m = /#invite=([A-Za-z0-9_-]+)/.exec(s);
	return m ? m[1]! : s;
}

type Mode = "signin" | "join" | "recover";

export function SignedOut({ invite }: { invite?: string }) {
	const [mode, setMode] = useState<Mode>(invite ? "join" : "signin");
	const [recoveryKey, setRecoveryKey] = useState<{ key: string; finish: () => Promise<void> } | null>(null);

	if (recoveryKey) {
		return (
			<AuthScreen subtitle="Account created">
				<RecoveryKeyView recoveryKey={recoveryKey.key} onDone={async () => {
					history.replaceState(null, "", location.pathname);
					await recoveryKey.finish();
				}} />
			</AuthScreen>
		);
	}

	return (
		<AuthScreen subtitle="Zero-knowledge secrets for your apps">
			<Tabs value={mode} onChange={setMode} items={[
				{ value: "signin", label: "Sign in" },
				{ value: "join", label: "Join" },
				{ value: "recover", label: "Recover" },
			]} />
			{mode === "signin" && <SignInForm />}
			{mode === "join" && <JoinForm invite={invite} onCreated={setRecoveryKey} />}
			{mode === "recover" && <RecoverForm />}
		</AuthScreen>
	);
}

function SignInForm() {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [totp, setTotp] = useState("");
	const [needTotp, setNeedTotp] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		setBusy(true);
		setError(null);
		try {
			await signIn(username, password, needTotp ? totp : undefined);
		} catch (err) {
			if (err instanceof TotpRequiredError) setNeedTotp(true);
			else setError(errorMessage(err));
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			<Label for="si-user">Username</Label>
			<Input id="si-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username} autofocus
				onInput={(e) => setUsername(e.currentTarget.value)} />
			<Label class="mt-1" for="si-pw">Password</Label>
			<Input id="si-pw" type="password" autocomplete="current-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			{needTotp && (
				<>
					<Label class="mt-1" for="si-totp">Two-step login code</Label>
					<Input id="si-totp" inputMode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxLength={6} value={totp} autofocus
						onInput={(e) => setTotp(e.currentTarget.value.replace(/\D/g, ""))} />
				</>
			)}
			<ErrorText>{error}</ErrorText>
			<Button type="submit" class="mt-1 w-full" disabled={busy || !username || !password || (needTotp && totp.length !== 6)}>
				{busy ? "Signing in…" : "Sign in"}
			</Button>
			<Hint class="text-xs">No account? Ask an admin for an invite link. There is no open sign-up.</Hint>
		</form>
	);
}

function JoinForm({ invite: initialInvite = "", onCreated }: {
	invite?: string;
	onCreated: (r: { key: string; finish: () => Promise<void> }) => void;
}) {
	const [invite, setInvite] = useState(initialInvite);
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [confirm, setConfirm] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		const err = validatePassword(password) ?? (password !== confirm ? "Passwords do not match" : null);
		if (err) return setError(err);
		setBusy(true);
		setError(null);
		try {
			const r = await joinWithInvite(parseInvite(invite), username, password);
			onCreated({ key: r.recoveryKey, finish: r.finish });
		} catch (e2) {
			setError(errorMessage(e2));
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			{!initialInvite && (
				<>
					<Label for="j-inv">Invite link</Label>
					<Input id="j-inv" autocomplete="off" spellcheck={false} value={invite} placeholder="https://…/#invite=…"
						onInput={(e) => setInvite(e.currentTarget.value)} />
				</>
			)}
			<Label class="mt-1" for="j-user">Choose a username</Label>
			<Input id="j-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				onInput={(e) => setUsername(e.currentTarget.value)} />
			<Hint class="text-xs">3–64 characters: a–z, 0–9, ".", "_" or "-".</Hint>
			<Label class="mt-1" for="j-pw">Choose a password</Label>
			<Input id="j-pw" type="password" autocomplete="new-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			<Hint class="text-xs">
				At least {MIN_PASSWORD_LENGTH} characters; a memorable passphrase works well. It encrypts your keys, so it
				cannot be reset without your recovery key.
			</Hint>
			<Label class="mt-1" for="j-pw2">Confirm password</Label>
			<Input id="j-pw2" type="password" autocomplete="new-password" value={confirm}
				onInput={(e) => setConfirm(e.currentTarget.value)} />
			<ErrorText>{error}</ErrorText>
			<Button type="submit" class="mt-1 w-full" disabled={busy || !invite || !username || !password}>
				{busy ? "Creating account…" : "Create account"}
			</Button>
		</form>
	);
}

function RecoverForm() {
	const [username, setUsername] = useState("");
	const [key, setKey] = useState("");
	const [password, setPassword] = useState("");
	const [confirm, setConfirm] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		const err = validatePassword(password) ?? (password !== confirm ? "Passwords do not match" : null);
		if (err) return setError(err);
		setBusy(true);
		setError(null);
		try {
			await recoverAccount(username, key, password);
		} catch (e2) {
			setError(errorMessage(e2));
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			<Hint>Set a new password with the recovery key you saved when the account was created. Two-step login is turned off; turn it on again afterwards.</Hint>
			<Label class="mt-1" for="r-user">Username</Label>
			<Input id="r-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				onInput={(e) => setUsername(e.currentTarget.value)} />
			<Label class="mt-1" for="r-key">Recovery key</Label>
			<Input id="r-key" class="font-mono" autocomplete="off" autocapitalize="characters" spellcheck={false} value={key}
				placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" onInput={(e) => setKey(e.currentTarget.value)} />
			<Label class="mt-1" for="r-pw">New password</Label>
			<Input id="r-pw" type="password" autocomplete="new-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			<Label class="mt-1" for="r-pw2">Confirm new password</Label>
			<Input id="r-pw2" type="password" autocomplete="new-password" value={confirm}
				onInput={(e) => setConfirm(e.currentTarget.value)} />
			<ErrorText>{error}</ErrorText>
			<Button type="submit" class="mt-1 w-full" disabled={busy || !username || !key || !password}>
				{busy ? "Recovering…" : "Set new password"}
			</Button>
		</form>
	);
}

/** Shown once after an account is created. */
export function RecoveryKeyView({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => Promise<void> }) {
	const [saved, setSaved] = useState(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	return (
		<div class="grid gap-4">
			<Alert variant="warning" icon={<TriangleAlert />} title="Save your recovery key now. It is shown only once.">
				It is the only way back into your account if you forget your password. Store it in a password manager (e.g.
				Bitwarden, Proton Pass) or write it down and keep it offline.
			</Alert>
			<p class="bg-muted rounded-lg border border-dashed px-4 py-4 text-center font-mono text-lg tracking-wide" aria-label="Recovery key">
				{recoveryKey.split("-").map((g, i) => (i ? <>-<wbr />{g}</> : g))}
			</p>
			<CopyButton value={recoveryKey} />
			<Checkbox checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)}>I saved my recovery key</Checkbox>
			<ErrorText>{error}</ErrorText>
			<Button class="w-full" disabled={!saved || busy} onClick={async () => {
				setBusy(true);
				try {
					await onDone();
				} catch (e) {
					setError(errorMessage(e));
					setBusy(false);
				}
			}}>{busy ? "Opening…" : "Continue"}</Button>
		</div>
	);
}

export function UnlockView({ account }: { account: AccountResponse }) {
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		setBusy(true);
		setError(null);
		try {
			await unlock(account, password);
		} catch (err) {
			setError(errorMessage(err));
			setBusy(false);
		}
	}

	return (
		<AuthScreen subtitle={`Locked · ${account.user.username}`}>
			<form class="grid gap-3" onSubmit={submit}>
				<input type="text" name="username" autocomplete="username" value={account.user.username} hidden readOnly />
				<Label for="u-pw">Password</Label>
				<Input id="u-pw" type="password" autocomplete="current-password" value={password} autofocus
					onInput={(e) => setPassword(e.currentTarget.value)} />
				<ErrorText>{error}</ErrorText>
				<Button type="submit" class="mt-1 w-full" disabled={busy || !password}>{busy ? "Unlocking…" : "Unlock"}</Button>
				<Button variant="ghost" class="w-full" onClick={() => void signOut().then(() => location.reload())}>
					Sign out
				</Button>
			</form>
		</AuthScreen>
	);
}
