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
import { ErrorText, Hint, Section } from "./common.tsx";
import { Alert, Badge, Button, Checkbox, Field, Input, Select } from "@cfsa/ui";
import { CircleCheck, Cloud, CloudOff, Copy, Link2, LogOut, RefreshCw, ShieldCheck, TriangleAlert, UserPlus } from "lucide-preact";

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
			<Section title="Sync">
				<RecoveryKeyView recoveryKey={recoveryKey} onDone={() => setRecoveryKey(null)} />
			</Section>
		);
	}

	if (!account) {
		return (
			<Section title="Sync">
				<div class="flex items-start gap-3">
					<CloudOff class="text-muted-foreground mt-0.5 size-5 shrink-0" />
					<Hint>
						Sync is off. Codes stay on this device only. Sign in, or create an account with an invite link from
						your server admin, to sync encrypted across devices.
					</Hint>
				</div>
				{mode === "none" && (
					<div class="grid grid-cols-2 gap-2">
						<Button variant="outline" onClick={() => setMode("signin")}>Sign in</Button>
						<Button variant="outline" onClick={() => setMode("join")}>Join with invite</Button>
					</div>
				)}
				{mode === "signin" && (
					<SignInForm
						note="After signing in, the account password unlocks this device. If the account already has a different vault, this device's codes are merged into it and PIN unlock is turned off."
						onDone={() => { setMode("none"); onPinMaybeRemoved(); }}
					/>
				)}
				{mode === "join" && <JoinForm invite={invite} createLocal={false} onRecoveryKey={(k) => { setMode("none"); setRecoveryKey(k); }} />}
				{mode !== "none" && <Button variant="link" onClick={() => setMode("none")}>Cancel</Button>}
			</Section>
		);
	}

	return (
		<>
			<Section title="Sync">
				<div class="flex items-center gap-3">
					<div class="bg-primary/10 text-primary grid size-10 place-items-center rounded-full"><Cloud class="size-5" /></div>
					<div class="grid min-w-0 flex-1 gap-0.5">
						<p class="truncate text-sm">
							Signed in as <strong>{account.username}</strong>
						</p>
						{sync?.status !== "signed_out" && (
							<p class={sync?.status === "error" ? "text-destructive text-xs" : "text-muted-foreground text-xs"}>
								{sync?.status === "ok" ? `Last synced ${ago(sync.lastSyncAt)}.` : sync?.message}
							</p>
						)}
					</div>
					{account.role === "admin" && <Badge variant="outline">admin</Badge>}
				</div>
				{sync?.status === "signed_out" && (
					<SignInForm username={account.username} note={sync.message} onDone={() => void syncNow()} />
				)}
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" disabled={busy} onClick={async () => { setBusy(true); await syncNow(); setBusy(false); }}>
						<RefreshCw class={busy ? "animate-spin" : ""} /> {busy ? "Syncing…" : "Sync now"}
					</Button>
					<Button variant="destructive-outline" onClick={async () => {
						if (confirm("Sign out of sync? Codes stay on this device; changes stop syncing.")) await signOut();
					}}><LogOut /> Sign out</Button>
				</div>
			</Section>

			<TotpSection account={account} />

			{account.role === "admin" && <InvitesSection />}
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
			<Section title="Two-step login">
				<div class="flex items-start gap-3">
					<ShieldCheck class="text-primary mt-0.5 size-5 shrink-0" />
					<div class="grid gap-1">
						<p class="text-sm font-medium">On <Badge class="ml-1">✓</Badge></p>
						<Hint>
							Signing in on a new device needs a code from your authenticator. If you lose it, use your recovery key:
							it sets a new password and turns two-step login off.
						</Hint>
					</div>
				</div>
				{disabling ? (
					<form class="grid gap-4" onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpDisable(password); setDisabling(false); setPassword(""); }); }}>
						<Field label="Password" htmlFor="td-pw">
							<Input id="td-pw" type="password" autocomplete="current-password" value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
						</Field>
						<div class="grid grid-cols-2 gap-2">
							<Button variant="outline" onClick={() => setDisabling(false)}>Cancel</Button>
							<Button variant="destructive" type="submit" disabled={busy || !password}>Turn off</Button>
						</div>
					</form>
				) : (
					<Button variant="destructive-outline" class="w-full" onClick={() => setDisabling(true)}>Turn off</Button>
				)}
				<ErrorText>{error}</ErrorText>
			</Section>
		);
	}

	if (!setup) {
		return (
			<Section title="Two-step login">
				<div class="flex items-center justify-between gap-2">
					<p class="text-sm font-medium">Off</p>
					<Badge variant="warning">recommended</Badge>
				</div>
				<Hint>Require a 6-digit code, in addition to your password, when this account signs in on a new device.</Hint>
				<TotpWarning />
				<Button class="w-full" disabled={busy} onClick={() => void run(async () => { setSetup(await totpSetup()); setAck(false); setCode(""); })}>
					<ShieldCheck /> Set up two-step login
				</Button>
				<ErrorText>{error}</ErrorText>
			</Section>
		);
	}

	const groupedKey = setup.secret.match(/.{1,4}/g)!.join(" ");
	return (
		<Section title="Two-step login">
			<form class="grid gap-4" onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpEnable(code); setSetup(null); setCode(""); }); }}>
				<div class="grid gap-1">
					<h3 class="text-sm font-semibold">1. Add it to a second authenticator</h3>
					<Hint>
						Scan with <strong>another phone</strong> or authenticator app, or put the setup key in your
						<strong> password manager</strong> (Bitwarden and Proton Pass can generate these codes).
						Not only in Tumbler on this device: you need the code to sign in to Tumbler.
					</Hint>
				</div>
				<QrCode value={setup.uri} label="Two-step login setup code" />
				<Field label="Setup key">
					<p class="bg-muted rounded-md px-3 py-2 font-mono text-base tracking-wider break-all" aria-label="Setup key">{groupedKey}</p>
				</Field>
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" onClick={async () => { await copySecret(setup.secret, 120); setCopied("key"); }}>
						<Copy /> {copied === "key" ? "Key copied (clears in 2 min)" : "Copy setup key"}
					</Button>
					<Button variant="outline" onClick={async () => { await copySecret(setup.uri, 120); setCopied("uri"); }}>
						<Link2 /> {copied === "uri" ? "Link copied (clears in 2 min)" : "Copy otpauth:// link"}
					</Button>
				</div>

				<h3 class="text-sm font-semibold">2. Confirm with a code</h3>
				<Field label="Code from the authenticator" htmlFor="te-code">
					<Input id="te-code" inputMode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxLength={6} value={code}
						class="font-mono tracking-widest" onInput={(e) => setCode(e.currentTarget.value.replace(/\D/g, ""))} />
				</Field>

				<Alert variant="warning" icon={<TriangleAlert />} title="Lockout risk.">
					With two-step login on, a lost or wiped authenticator means you cannot sign in on a new device. Only your
					<strong> recovery key</strong> gets you back in (it also turns two-step login off).
				</Alert>
				<Checkbox checked={ack} onChange={(e) => setAck(e.currentTarget.checked)}>
					I saved this code on a second device or in my password manager, and my recovery key is in my password
					manager or written down.
				</Checkbox>
				<div class="grid grid-cols-2 gap-2">
					<Button variant="outline" onClick={() => setSetup(null)}>Cancel</Button>
					<Button type="submit" disabled={busy || code.length !== 6 || !ack}>Turn on</Button>
				</div>
				<ErrorText>{error}</ErrorText>
			</form>
		</Section>
	);
}

function TotpWarning() {
	return (
		<Alert variant="warning" icon={<TriangleAlert />} title="More security, but a lockout risk.">
			<p>A stolen password alone will no longer be enough to sign in. But if you lose the codes, you are locked out of new devices.</p>
			<p>Before turning it on:</p>
			<ul>
				<li>Scan the code with a <strong>second phone</strong>, or save the setup key in your <strong>password manager</strong>.</li>
				<li>Keep your <strong>recovery key</strong> in your password manager or written down offline. It is the way back in.</li>
				<li>Do not keep this code only in Tumbler: you need it to sign in to Tumbler.</li>
			</ul>
		</Alert>
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
		<Section title="Invite users" description="Invite links work once and expire after 24 hours. There is no open sign-up.">
			<div class="grid grid-cols-[1fr_auto] items-end gap-2">
				<Field label="Role" htmlFor="inv-role">
					<Select id="inv-role" value={role} onChange={(e) => setRole(e.currentTarget.value as "user" | "admin")}>
						<option value="user">User</option>
						<option value="admin">Admin</option>
					</Select>
				</Field>
				<Button onClick={create}><UserPlus /> Create invite link</Button>
			</div>
			{created && (
				<Alert variant="success" icon={<CircleCheck />} title="Send this link to the person you are inviting. It is shown only now.">
					<p class="bg-background rounded-md border px-3 py-2 font-mono text-xs break-all" aria-label="Invite link">{created.link}</p>
					<div class="mt-1 grid grid-cols-2 gap-2">
						<Button variant="outline" onClick={async () => { await copySecret(created.link, 0); setCopied(true); }}>
							<Copy /> {copied ? "Copied" : "Copy link"}
						</Button>
						<Button variant="outline" onClick={() => setCreated(null)}>Done</Button>
					</div>
				</Alert>
			)}
			<ErrorText>{error}</ErrorText>
			{pending.length > 0 && (
				<div class="grid gap-2">
					<p class="text-sm font-medium">Pending</p>
					<ul class="divide-y rounded-lg border">
						{pending.map((i) => (
							<li class="flex items-center justify-between gap-2 px-3 py-2 text-sm">
								<span><Badge variant="outline" class="mr-2">{i.role}</Badge>expires {new Date(i.expiresAt).toLocaleString()}</span>
								<Button variant="ghost" size="sm" class="text-destructive" onClick={async () => { await revokeInvite(i.id); await reload(); }}>Revoke</Button>
							</li>
						))}
					</ul>
				</div>
			)}
			{used.length > 0 && <Hint>Used by: {used.map((i) => i.usedBy).join(", ")}</Hint>}
		</Section>
	);
}
