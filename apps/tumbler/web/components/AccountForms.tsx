import { useState } from "preact/hooks";
import { joinWithInvite, recoverAccount, signIn, TotpRequiredError } from "../lib/account.ts";
import { MIN_PASSWORD_LENGTH, validatePassword } from "../lib/vault-core.ts";
import { copySecret } from "../lib/clipboard.ts";
import * as vault from "../lib/vault.ts";
import { ErrorText, Hint } from "./common.tsx";
import { Alert, Button, Checkbox, Input, Label } from "./ui/index.tsx";
import { Copy, TriangleAlert } from "lucide-preact";

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Extract the token from a pasted invite link or a bare token. */
export function parseInvite(input: string): string {
	const s = input.trim();
	const m = /#invite=([A-Za-z0-9_-]+)/.exec(s);
	return m ? m[1]! : s;
}

export function SignInForm({ username: initialUser = "", onDone, note }: { username?: string; onDone: () => void; note?: string }) {
	const [username, setUsername] = useState(initialUser);
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
			onDone();
		} catch (err) {
			if (err instanceof TotpRequiredError) {
				setNeedTotp(true);
				setError(null);
			} else setError(msg(err));
		} finally {
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			<Hint>{note}</Hint>
			<Label class="mt-1" for="si-user">Username</Label>
			<Input id="si-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				readOnly={!!initialUser} onInput={(e) => setUsername(e.currentTarget.value)} />
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
		</form>
	);
}

/**
 * Join with an invite. `createLocal`: no vault on this device yet, so create one with the same password.
 * Calls onRecoveryKey with the recovery key, which the caller must show once.
 */
export function JoinForm({ invite: initialInvite = "", createLocal, onRecoveryKey }: {
	invite?: string;
	createLocal: boolean;
	onRecoveryKey: (key: string) => void;
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
			// After a failed attempt the vault already exists and is still unlocked; reuse it.
			if (createLocal && !(await vault.hasVault())) await vault.createVault(password);
			onRecoveryKey(await joinWithInvite(parseInvite(invite), username, password));
		} catch (e2) {
			setError(msg(e2));
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			{!initialInvite && (
				<>
					<Label class="mt-1" for="j-inv">Invite link</Label>
					<Input id="j-inv" autocomplete="off" spellcheck={false} value={invite} placeholder="https://…/#invite=…"
						onInput={(e) => setInvite(e.currentTarget.value)} />
				</>
			)}
			<Label class="mt-1" for="j-user">Choose a username</Label>
			<Input id="j-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				onInput={(e) => setUsername(e.currentTarget.value)} />
			<Hint class="text-xs">3–64 characters: a–z, 0–9, ".", "_" or "-".</Hint>
			<Label class="mt-1" for="j-pw">{createLocal ? "Choose a password" : "Account password"}</Label>
			<Input id="j-pw" type="password" autocomplete="new-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			<Hint class="text-xs">
				At least {MIN_PASSWORD_LENGTH} characters; a memorable passphrase works well.
				{!createLocal && " It becomes the master password on this device too."}
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

export function RecoverForm({ username: initialUser = "", onDone }: { username?: string; onDone: () => void }) {
	const [username, setUsername] = useState(initialUser);
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
			onDone();
		} catch (e2) {
			setError(msg(e2));
			setBusy(false);
		}
	}

	return (
		<form class="grid gap-3" onSubmit={submit}>
			<Hint>Sets a new password using the recovery key you saved when the account was created. Two-step login is turned off; turn it on again afterwards.</Hint>
			<Label class="mt-1" for="r-user">Username</Label>
			<Input id="r-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				readOnly={!!initialUser} onInput={(e) => setUsername(e.currentTarget.value)} />
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
export function RecoveryKeyView({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => void }) {
	const [saved, setSaved] = useState(false);
	const [copied, setCopied] = useState(false);
	return (
		<div class="grid gap-4">
			<Alert variant="warning" icon={<TriangleAlert />} title="Save your recovery key now. It is shown only once.">
				It is the only way back into your account if you forget your password. Store it in a password manager (e.g.
				Bitwarden, Proton Pass) or write it down and keep it offline.
			</Alert>
			<p class="bg-muted rounded-lg border border-dashed px-4 py-4 text-center font-mono text-lg tracking-wide" aria-label="Recovery key">
				{recoveryKey.split("-").map((g, i) => (i ? <>-<wbr />{g}</> : g))}
			</p>
			<Button variant="outline" class="w-full" onClick={async () => { await copySecret(recoveryKey, 120); setCopied(true); }}>
				<Copy /> {copied ? "Copied (clears in 2 min)" : "Copy"}
			</Button>
			<Checkbox checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)}>I saved my recovery key</Checkbox>
			<Button class="w-full" disabled={!saved} onClick={onDone}>Continue</Button>
		</div>
	);
}
