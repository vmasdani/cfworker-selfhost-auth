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
				<p class="hint">On. Signing in to this account on a new device needs a code from your authenticator.</p>
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

	return (
		<div class="settings-group">
			<p class="hint">
				Off. Turn on to require a 6-digit code when signing in on a new device. Keep the code in a
				<strong> different</strong> authenticator, or you could lock yourself out. The recovery key also turns it off.
			</p>
			{setup ? (
				<form onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpEnable(code); setSetup(null); setCode(""); }); }}>
					<QrCode value={setup.uri} label="Two-step login setup code" />
					<p class="hint mono break">{setup.secret.match(/.{1,4}/g)!.join(" ")}</p>
					<label for="te-code">Code from the authenticator</label>
					<input id="te-code" inputMode="numeric" autocomplete="one-time-code" maxLength={6} value={code}
						onInput={(e) => setCode(e.currentTarget.value.replace(/\D/g, ""))} />
					<div class="actions">
						<button type="button" onClick={() => setSetup(null)}>Cancel</button>
						<button class="primary" type="submit" disabled={busy || code.length !== 6}>Turn on</button>
					</div>
				</form>
			) : (
				<div class="actions"><button disabled={busy} onClick={() => void run(async () => setSetup(await totpSetup()))}>Set up</button></div>
			)}
			{error && <p class="error">{error}</p>}
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
