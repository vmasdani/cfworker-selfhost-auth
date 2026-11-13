import { useState } from "preact/hooks";
import { joinWithInvite, recoverAccount, signIn, TotpRequiredError } from "../lib/account.ts";
import { MIN_PASSWORD_LENGTH, validatePassword } from "../lib/vault-core.ts";
import { copySecret } from "../lib/clipboard.ts";
import * as vault from "../lib/vault.ts";

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
		<form onSubmit={submit}>
			{note && <p class="hint">{note}</p>}
			<label for="si-user">Username</label>
			<input id="si-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				readOnly={!!initialUser} onInput={(e) => setUsername(e.currentTarget.value)} />
			<label for="si-pw">Password</label>
			<input id="si-pw" type="password" autocomplete="current-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			{needTotp && (
				<>
					<label for="si-totp">Two-step login code</label>
					<input id="si-totp" inputMode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxLength={6} value={totp} autofocus
						onInput={(e) => setTotp(e.currentTarget.value.replace(/\D/g, ""))} />
				</>
			)}
			{error && <p class="error">{error}</p>}
			<button class="primary block" type="submit" disabled={busy || !username || !password || (needTotp && totp.length !== 6)}>
				{busy ? "Signing in…" : "Sign in"}
			</button>
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
		<form onSubmit={submit}>
			{!initialInvite && (
				<>
					<label for="j-inv">Invite link</label>
					<input id="j-inv" autocomplete="off" spellcheck={false} value={invite} placeholder="https://…/#invite=…"
						onInput={(e) => setInvite(e.currentTarget.value)} />
				</>
			)}
			<label for="j-user">Choose a username</label>
			<input id="j-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				onInput={(e) => setUsername(e.currentTarget.value)} />
			<p class="hint">3–64 characters: a–z, 0–9, ".", "_" or "-".</p>
			<label for="j-pw">{createLocal ? "Choose a password" : "Account password"}</label>
			<input id="j-pw" type="password" autocomplete="new-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			<p class="hint">
				At least {MIN_PASSWORD_LENGTH} characters; a memorable passphrase works well.
				{!createLocal && " It becomes the master password on this device too."}
			</p>
			<label for="j-pw2">Confirm password</label>
			<input id="j-pw2" type="password" autocomplete="new-password" value={confirm}
				onInput={(e) => setConfirm(e.currentTarget.value)} />
			{error && <p class="error">{error}</p>}
			<button class="primary block" type="submit" disabled={busy || !invite || !username || !password}>
				{busy ? "Creating account…" : "Create account"}
			</button>
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
		<form onSubmit={submit}>
			<p class="hint">Sets a new password using the recovery key you saved when the account was created. Two-step login is turned off; turn it on again afterwards.</p>
			<label for="r-user">Username</label>
			<input id="r-user" autocomplete="username" autocapitalize="none" spellcheck={false} value={username}
				readOnly={!!initialUser} onInput={(e) => setUsername(e.currentTarget.value)} />
			<label for="r-key">Recovery key</label>
			<input id="r-key" class="mono" autocomplete="off" autocapitalize="characters" spellcheck={false} value={key}
				placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" onInput={(e) => setKey(e.currentTarget.value)} />
			<label for="r-pw">New password</label>
			<input id="r-pw" type="password" autocomplete="new-password" value={password}
				onInput={(e) => setPassword(e.currentTarget.value)} />
			<label for="r-pw2">Confirm new password</label>
			<input id="r-pw2" type="password" autocomplete="new-password" value={confirm}
				onInput={(e) => setConfirm(e.currentTarget.value)} />
			{error && <p class="error">{error}</p>}
			<button class="primary block" type="submit" disabled={busy || !username || !key || !password}>
				{busy ? "Recovering…" : "Set new password"}
			</button>
		</form>
	);
}

/** Shown once after an account is created. */
export function RecoveryKeyView({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => void }) {
	const [saved, setSaved] = useState(false);
	const [copied, setCopied] = useState(false);
	return (
		<div>
			<div class="notice warn">
				<strong>Save your recovery key now. It is shown only once.</strong> It is the only way back into your
				account if you forget your password. Store it in a password manager (e.g. Bitwarden, Proton Pass) or
				write it down and keep it offline.
			</div>
			<p class="recovery-key mono" aria-label="Recovery key">
				{recoveryKey.split("-").map((g, i) => (i ? <>-<wbr />{g}</> : g))}
			</p>
			<div class="actions">
				<button type="button" onClick={async () => { await copySecret(recoveryKey, 120); setCopied(true); }}>
					{copied ? "Copied (clears in 2 min)" : "Copy"}
				</button>
			</div>
			<label class="check">
				<input type="checkbox" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
				I saved my recovery key
			</label>
			<button class="primary block" disabled={!saved} onClick={onDone}>Continue</button>
		</div>
	);
}
