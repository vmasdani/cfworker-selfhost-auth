import { useEffect, useState } from "preact/hooks";
import {
	createInvite,
	getAccount,
	getSyncState,
	inviteLink,
	listInvites,
	revokeInvite,
	signOut,
	syncEvents,
	syncNow,
	totpDisable,
	totpEnable,
	totpSetup,
	type AccountInfo,
	type SyncState,
} from "../lib/account.ts";
import type { Invite } from "../lib/api.ts";
import { copySecret } from "../lib/clipboard.ts";
import { JoinForm, RecoveryKeyView, SignInForm } from "./AccountForms.tsx";
import { QrCode } from "./QrCode.tsx";

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function useAccount(): { account: AccountInfo | null | undefined; sync: SyncState | null } {
	const [account, setAccount] = useState<AccountInfo | null | undefined>(undefined);
	const [sync, setSync] = useState<SyncState | null>(null);
	useEffect(() => {
		const load = async () => {
			setAccount((await getAccount()) ?? null);
			setSync(await getSyncState());
		};
		void load();
		syncEvents.addEventListener("state", load);
		return () => syncEvents.removeEventListener("state", load);
	}, []);
	return { account, sync };
}

function ago(ts: number | null): string {
	if (!ts) return "never";
	const s = Math.round((Date.now() - ts) / 1000);
	if (s < 60) return "just now";
	if (s < 3600) return `${Math.round(s / 60)} min ago`;
	return new Date(ts).toLocaleString();
}

export function AccountSection({ invite, onPinMaybeRemoved }: { invite?: string; onPinMaybeRemoved: () => void }) {
	const { account, sync } = useAccount();
	const [mode, setMode] = useState<"none" | "signin" | "join">(invite ? "join" : "none");
	const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	if (account === undefined) return null;

	if (recoveryKey) {
		return (
			<div class="settings-group">
				<RecoveryKeyView recoveryKey={recoveryKey} onDone={() => setRecoveryKey(null)} />
			</div>
		);
	}

	if (!account) {
		return (
			<div class="settings-group">
				<p class="hint">
					Sync is off. Codes stay on this device only. Sign in, or create an account with an invite link from
					your server admin, to sync encrypted across devices.
				</p>
				{mode === "none" && (
					<div class="actions">
						<button onClick={() => setMode("signin")}>Sign in</button>
						<button onClick={() => setMode("join")}>Join with invite</button>
					</div>
				)}
				{mode === "signin" && (
					<SignInForm
						note="After signing in, the account password unlocks this device. If the account already has a different vault, this device's codes are merged into it and PIN unlock is turned off."
						onDone={() => { setMode("none"); onPinMaybeRemoved(); }}
					/>
				)}
				{mode === "join" && <JoinForm invite={invite} createLocal={false} onRecoveryKey={(k) => { setMode("none"); setRecoveryKey(k); }} />}
				{mode !== "none" && <button class="link" onClick={() => setMode("none")}>Cancel</button>}
			</div>
		);
	}

	return (
		<>
			<div class="settings-group">
				<p>
					Signed in as <strong>{account.username}</strong>
					{account.role === "admin" && <span class="badge">admin</span>}
				</p>
				{sync?.status === "signed_out" ? (
					<SignInForm username={account.username} note={sync.message} onDone={() => void syncNow()} />
				) : (
					<p class={sync?.status === "error" ? "error" : "hint"}>
						{sync?.status === "ok" ? `Last synced ${ago(sync.lastSyncAt)}.` : sync?.message}
					</p>
				)}
				<div class="actions">
					<button disabled={busy} onClick={async () => { setBusy(true); await syncNow(); setBusy(false); }}>
						{busy ? "Syncing…" : "Sync now"}
					</button>
					<button class="danger" onClick={async () => {
						if (confirm("Sign out of sync? Codes stay on this device; changes stop syncing.")) await signOut();
					}}>Sign out</button>
				</div>
			</div>

			<h2>Two-step login</h2>
			<TotpSection account={account} />

			{account.role === "admin" && (
				<>
					<h2>Invite users</h2>
					<InvitesSection />
				</>
			)}
		</>
	);
}

function TotpSection({ account }: { account: AccountInfo }) {
	const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
	const [code, setCode] = useState("");
	const [password, setPassword] = useState("");
	const [disabling, setDisabling] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [ack, setAck] = useState(false);
	const [copied, setCopied] = useState<"key" | "uri" | null>(null);

	const run = async (fn: () => Promise<void>) => {
		setBusy(true);
		setError(null);
		try {
			await fn();
		} catch (e) {
			setError(msg(e));
		} finally {
			setBusy(false);
		}
	};

	if (account.totpEnabled) {
		return (
			<div class="settings-group">
				<p>On <span class="badge">✓</span></p>
				<p class="hint">
					Signing in on a new device needs a code from your authenticator. If you lose it, use your recovery key:
					it sets a new password and turns two-step login off.
				</p>
				{disabling ? (
					<form onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpDisable(password); setDisabling(false); setPassword(""); }); }}>
						<label for="td-pw">Password</label>
						<input id="td-pw" type="password" autocomplete="current-password" value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
						<div class="actions">
							<button type="button" onClick={() => setDisabling(false)}>Cancel</button>
							<button class="danger" type="submit" disabled={busy || !password}>Turn off</button>
						</div>
					</form>
				) : (
					<div class="actions"><button class="danger" onClick={() => setDisabling(true)}>Turn off</button></div>
				)}
				{error && <p class="error">{error}</p>}
			</div>
		);
	}

	if (!setup) {
		return (
			<div class="settings-group">
				<p>Off <span class="badge">recommended</span></p>
				<p class="hint">Require a 6-digit code, in addition to your password, when this account signs in on a new device.</p>
				<TotpWarning />
				<div class="actions">
					<button class="primary" disabled={busy} onClick={() => void run(async () => { setSetup(await totpSetup()); setAck(false); setCode(""); })}>
						Set up two-step login
					</button>
				</div>
				{error && <p class="error">{error}</p>}
			</div>
		);
	}

	const groupedKey = setup.secret.match(/.{1,4}/g)!.join(" ");
	return (
		<form class="settings-group" onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpEnable(code); setSetup(null); setCode(""); }); }}>
			<h3>1. Add it to a second authenticator</h3>
			<p class="hint">
				Scan with <strong>another phone</strong> or authenticator app, or put the setup key in your
				<strong> password manager</strong> (Bitwarden and Proton Pass can generate these codes).
				Not only in Tumbler on this device: you need the code to sign in to Tumbler.
			</p>
			<QrCode value={setup.uri} label="Two-step login setup code" />
			<label>Setup key</label>
			<p class="mono break setup-key" aria-label="Setup key">{groupedKey}</p>
			<div class="actions">
				<button type="button" onClick={async () => { await copySecret(setup.secret, 120); setCopied("key"); }}>
					{copied === "key" ? "Key copied (clears in 2 min)" : "Copy setup key"}
				</button>
				<button type="button" onClick={async () => { await copySecret(setup.uri, 120); setCopied("uri"); }}>
					{copied === "uri" ? "Link copied (clears in 2 min)" : "Copy otpauth:// link"}
				</button>
			</div>

			<h3>2. Confirm with a code</h3>
			<label for="te-code">Code from the authenticator</label>
			<input id="te-code" inputMode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxLength={6} value={code}
				onInput={(e) => setCode(e.currentTarget.value.replace(/\D/g, ""))} />

			<div class="notice warn">
				<strong>Lockout risk.</strong> With two-step login on, a lost or wiped authenticator means you cannot sign in
				on a new device. Only your <strong>recovery key</strong> gets you back in (it also turns two-step login off).
			</div>
			<label class="check">
				<input type="checkbox" checked={ack} onChange={(e) => setAck(e.currentTarget.checked)} />
				I saved this code on a second device or in my password manager, and my recovery key is in my password
				manager or written down.
			</label>
			<div class="actions">
				<button type="button" onClick={() => setSetup(null)}>Cancel</button>
				<button class="primary" type="submit" disabled={busy || code.length !== 6 || !ack}>Turn on</button>
			</div>
			{error && <p class="error">{error}</p>}
		</form>
	);
}

function TotpWarning() {
	return (
		<div class="notice warn">
			<p><strong>More security, but a lockout risk.</strong> A stolen password alone will no longer be enough to sign in.
				But if you lose the codes, you are locked out of new devices.</p>
			<p>Before turning it on:</p>
			<ul>
				<li>Scan the code with a <strong>second phone</strong>, or save the setup key in your <strong>password manager</strong>.</li>
				<li>Keep your <strong>recovery key</strong> in your password manager or written down offline. It is the way back in.</li>
				<li>Do not keep this code only in Tumbler: you need it to sign in to Tumbler.</li>
			</ul>
		</div>
	);
}

function InvitesSection() {
	const [invites, setInvites] = useState<Invite[] | null>(null);
	const [created, setCreated] = useState<{ link: string; expiresAt: number } | null>(null);
	const [role, setRole] = useState<"user" | "admin">("user");
	const [copied, setCopied] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const reload = () => listInvites().then(setInvites).catch((e) => setError(msg(e)));
	useEffect(() => { void reload(); }, []);

	async function create() {
		setError(null);
		setCopied(false);
		try {
			const r = await createInvite(role);
			setCreated({ link: inviteLink(r.token), expiresAt: r.expiresAt });
			await reload();
		} catch (e) {
			setError(msg(e));
		}
	}

	const pending = invites?.filter((i) => !i.usedAt && i.expiresAt > Date.now()) ?? [];
	const used = invites?.filter((i) => i.usedAt) ?? [];

	return (
		<div class="settings-group">
			<p class="hint">Invite links work once and expire after 24 hours. There is no open sign-up.</p>
			<div class="row">
				<div>
					<label for="inv-role">Role</label>
					<select id="inv-role" value={role} onChange={(e) => setRole(e.currentTarget.value as "user" | "admin")}>
						<option value="user">User</option>
						<option value="admin">Admin</option>
					</select>
				</div>
				<div class="actions align-end"><button class="primary" onClick={create}>Create invite link</button></div>
			</div>
			{created && (
				<div class="notice">
					<p>Send this link to the person you are inviting. It is shown only now.</p>
					<p class="mono break" aria-label="Invite link">{created.link}</p>
					<div class="actions">
						<button onClick={async () => { await copySecret(created.link, 0); setCopied(true); }}>{copied ? "Copied" : "Copy link"}</button>
						<button onClick={() => setCreated(null)}>Done</button>
					</div>
				</div>
			)}
			{error && <p class="error">{error}</p>}
			{pending.length > 0 && (
				<>
					<label>Pending</label>
					<ul class="import-list">
						{pending.map((i) => (
							<li class="invite-row">
								<span>{i.role} · expires {new Date(i.expiresAt).toLocaleString()}</span>
								<button class="link danger" onClick={async () => { await revokeInvite(i.id); await reload(); }}>Revoke</button>
							</li>
						))}
					</ul>
				</>
			)}
			{used.length > 0 && <p class="hint">Used by: {used.map((i) => i.usedBy).join(", ")}</p>}
		</div>
	);
}
