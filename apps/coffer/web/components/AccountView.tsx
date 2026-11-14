import { Alert, Badge, Button, Checkbox, Field, Input, Select } from "@cfsa/ui";
import { CircleCheck, KeyRound, LogOut, ShieldCheck, TriangleAlert, UserPlus } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import type { Invite, UserSummary } from "../lib/api.ts";
import {
	changePassword,
	createInvite,
	listInvites,
	listUsers,
	revokeInvite,
	signOut,
	totpDisable,
	totpEnable,
	totpSetup,
	unlocked,
	validatePassword,
} from "../lib/session.ts";
import { CopyButton, ErrorText, errorMessage, Hint, Section, timeAgo } from "./common.tsx";
import { QrCode } from "./QrCode.tsx";

export function AccountView() {
	const u = unlocked()!;
	return (
		<div class="mx-auto grid max-w-2xl gap-8">
			<div class="flex flex-wrap items-center justify-between gap-3">
				<div>
					<h1 class="text-2xl font-semibold tracking-tight">{u.me.username}</h1>
					<p class="text-muted-foreground text-sm">{u.me.role === "admin" ? "Administrator" : "User"}</p>
				</div>
				<Button variant="outline" onClick={() => void signOut().then(() => location.reload())}><LogOut /> Sign out</Button>
			</div>

			<Section title="Your key" description="Project owners encrypt project keys to this public key when they add you.">
				<div class="flex items-start gap-3">
					<KeyRound class="text-primary mt-0.5 size-5 shrink-0" />
					<div class="grid gap-1">
						<p class="text-sm">Fingerprint</p>
						<code class="font-mono text-base tracking-wide">{u.fingerprint}</code>
						<Hint class="text-xs">When someone adds you to a project, they see this fingerprint. Compare it over another channel to rule out a tampered server.</Hint>
					</div>
				</div>
			</Section>

			<TotpSection />
			<PasswordSection />
			{u.me.role === "admin" && <InvitesSection />}
			{u.me.role === "admin" && <UsersSection />}
		</div>
	);
}

function TotpSection() {
	const enabled = unlocked()!.me.totpEnabled;
	const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
	const [code, setCode] = useState("");
	const [password, setPassword] = useState("");
	const [disabling, setDisabling] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [ack, setAck] = useState(false);

	const run = async (fn: () => Promise<void>) => {
		setBusy(true);
		setError(null);
		try {
			await fn();
		} catch (e) {
			setError(errorMessage(e));
		} finally {
			setBusy(false);
		}
	};

	if (enabled) {
		return (
			<Section title="Two-step login">
				<div class="flex items-start gap-3">
					<ShieldCheck class="text-primary mt-0.5 size-5 shrink-0" />
					<div class="grid gap-1">
						<p class="text-sm font-medium">On <Badge class="ml-1">✓</Badge></p>
						<Hint>Signing in needs a code from your authenticator. If you lose it, use your recovery key: it sets a new password and turns two-step login off.</Hint>
					</div>
				</div>
				{disabling ? (
					<form class="grid gap-4" onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpDisable(password); setDisabling(false); setPassword(""); }); }}>
						<Field label="Password" htmlFor="td-pw">
							<Input id="td-pw" type="password" autocomplete="current-password" value={password} onInput={(e) => setPassword(e.currentTarget.value)} />
						</Field>
						<div class="flex justify-end gap-2">
							<Button variant="outline" onClick={() => setDisabling(false)}>Cancel</Button>
							<Button variant="destructive" type="submit" disabled={busy || !password}>Turn off</Button>
						</div>
					</form>
				) : (
					<div><Button variant="destructive-outline" onClick={() => setDisabling(true)}>Turn off</Button></div>
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
				<Hint>Require a 6-digit code, in addition to your password, when you sign in.</Hint>
				<Alert variant="warning" icon={<TriangleAlert />} title="More security, but a lockout risk.">
					<p>A stolen password alone will no longer be enough to sign in. But if you lose the codes, you are locked out.</p>
					<p>Before turning it on:</p>
					<ul>
						<li>Scan the code with a <strong>second phone</strong> as well, or save the setup key in your <strong>password manager</strong>.</li>
						<li>Keep your <strong>recovery key</strong> in your password manager or written down offline. It is the way back in.</li>
					</ul>
				</Alert>
				<div>
					<Button disabled={busy} onClick={() => void run(async () => { setSetup(await totpSetup()); setAck(false); setCode(""); })}>
						<ShieldCheck /> Set up two-step login
					</Button>
				</div>
				<ErrorText>{error}</ErrorText>
			</Section>
		);
	}

	return (
		<Section title="Two-step login">
			<form class="grid gap-4" onSubmit={(e) => { e.preventDefault(); void run(async () => { await totpEnable(code); setSetup(null); setCode(""); }); }}>
				<div class="grid gap-1">
					<h3 class="text-sm font-semibold">1. Add it to your authenticator, and a backup</h3>
					<Hint>Scan with your authenticator app (e.g. Tumbler) <strong>and</strong> a second phone, or put the setup key in your password manager (Bitwarden and Proton Pass can generate these codes).</Hint>
				</div>
				<div class="max-w-64"><QrCode value={setup.uri} label="Two-step login setup code" /></div>
				<Field label="Setup key">
					<p class="bg-muted rounded-md px-3 py-2 font-mono text-base tracking-wider break-all" aria-label="Setup key">{setup.secret.match(/.{1,4}/g)!.join(" ")}</p>
				</Field>
				<div class="flex flex-wrap gap-2">
					<CopyButton value={setup.secret} label="Copy setup key" />
					<CopyButton value={setup.uri} label="Copy otpauth:// link" />
				</div>
				<h3 class="text-sm font-semibold">2. Confirm with a code</h3>
				<Field label="Code from the authenticator" htmlFor="te-code">
					<Input id="te-code" inputMode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxLength={6} value={code}
						class="max-w-40 font-mono tracking-widest" onInput={(e) => setCode(e.currentTarget.value.replace(/\D/g, ""))} />
				</Field>
				<Alert variant="warning" icon={<TriangleAlert />} title="Lockout risk.">
					With two-step login on, a lost or wiped authenticator means you cannot sign in. Only your <strong>recovery key</strong> gets
					you back in (it also turns two-step login off).
				</Alert>
				<Checkbox checked={ack} onChange={(e) => setAck(e.currentTarget.checked)}>
					I saved this code on a second device or in my password manager, and my recovery key is in my password manager or written down.
				</Checkbox>
				<div class="flex justify-end gap-2">
					<Button variant="outline" onClick={() => setSetup(null)}>Cancel</Button>
					<Button type="submit" disabled={busy || code.length !== 6 || !ack}>Turn on</Button>
				</div>
				<ErrorText>{error}</ErrorText>
			</form>
		</Section>
	);
}

function PasswordSection() {
	const [current, setCurrent] = useState("");
	const [next, setNext] = useState("");
	const [confirm, setConfirm] = useState("");
	const [msg, setMsg] = useState<{ error: boolean; text: string } | null>(null);
	const [busy, setBusy] = useState(false);

	async function save(e: Event) {
		e.preventDefault();
		const err = validatePassword(next) ?? (next !== confirm ? "Passwords do not match" : null);
		if (err) return setMsg({ error: true, text: err });
		setBusy(true);
		try {
			await changePassword(current, next);
			setCurrent("");
			setNext("");
			setConfirm("");
			setMsg({ error: false, text: "Password changed. Other sessions were signed out. Update it in your password manager." });
		} catch (e2) {
			setMsg({ error: true, text: errorMessage(e2) });
		} finally {
			setBusy(false);
		}
	}

	return (
		<Section title="Password">
			<form class="grid gap-4" onSubmit={save}>
				<input type="text" name="username" autocomplete="username" value={unlocked()!.me.username} hidden readOnly />
				<Field label="Current password" htmlFor="cp-cur">
					<Input id="cp-cur" type="password" autocomplete="current-password" value={current} onInput={(e) => setCurrent(e.currentTarget.value)} />
				</Field>
				<div class="grid gap-4 sm:grid-cols-2">
					<Field label="New password" htmlFor="cp-new">
						<Input id="cp-new" type="password" autocomplete="new-password" value={next} onInput={(e) => setNext(e.currentTarget.value)} />
					</Field>
					<Field label="Confirm new password" htmlFor="cp-new2">
						<Input id="cp-new2" type="password" autocomplete="new-password" value={confirm} onInput={(e) => setConfirm(e.currentTarget.value)} />
					</Field>
				</div>
				{msg && (msg.error ? <ErrorText>{msg.text}</ErrorText> : <Hint>{msg.text}</Hint>)}
				<div><Button type="submit" disabled={busy || !current || !next}>{busy ? "Changing…" : "Change password"}</Button></div>
			</form>
		</Section>
	);
}

function InvitesSection() {
	const [invites, setInvites] = useState<Invite[] | null>(null);
	const [created, setCreated] = useState<{ link: string; expiresAt: number } | null>(null);
	const [role, setRole] = useState<"user" | "admin">("user");
	const [hours, setHours] = useState(24);
	const [error, setError] = useState<string | null>(null);

	const reload = () => listInvites().then(setInvites).catch((e) => setError(errorMessage(e)));
	useEffect(() => void reload(), []);

	async function create() {
		setError(null);
		try {
			const r = await createInvite(role, hours);
			setCreated({ link: `${location.origin}/#invite=${r.token}`, expiresAt: r.expiresAt });
			await reload();
		} catch (e) {
			setError(errorMessage(e));
		}
	}

	const pending = invites?.filter((i) => !i.usedAt && i.expiresAt > Date.now()) ?? [];
	const used = invites?.filter((i) => i.usedAt) ?? [];

	return (
		<Section title="Invite users" description="Invite links work once and expire. There is no open sign-up.">
			<div class="grid items-end gap-2 sm:grid-cols-[1fr_1fr_auto]">
				<Field label="Role" htmlFor="inv-role">
					<Select id="inv-role" value={role} onChange={(e) => setRole(e.currentTarget.value as "user" | "admin")}>
						<option value="user">User</option>
						<option value="admin">Admin</option>
					</Select>
				</Field>
				<Field label="Expires after" htmlFor="inv-ttl">
					<Select id="inv-ttl" value={hours} onChange={(e) => setHours(Number(e.currentTarget.value))}>
						<option value={1}>1 hour</option>
						<option value={24}>24 hours</option>
						<option value={72}>3 days</option>
						<option value={168}>7 days</option>
					</Select>
				</Field>
				<Button onClick={create}><UserPlus /> Create invite link</Button>
			</div>
			{created && (
				<Alert variant="success" icon={<CircleCheck />} title="Send this link to the person you are inviting. It is shown only now.">
					<p class="bg-background rounded-md border px-3 py-2 font-mono text-xs break-all" aria-label="Invite link">{created.link}</p>
					<div class="mt-1 flex flex-wrap gap-2">
						<CopyButton value={created.link} label="Copy link" secret={false} />
						<Button variant="outline" size="sm" onClick={() => setCreated(null)}>Done</Button>
					</div>
				</Alert>
			)}
			<ErrorText>{error}</ErrorText>
			{pending.length > 0 && (
				<ul class="divide-y rounded-lg border">
					{pending.map((i) => (
						<li key={i.id} class="flex items-center justify-between gap-2 px-3 py-2 text-sm">
							<span><Badge variant="outline" class="mr-2">{i.role}</Badge>expires {new Date(i.expiresAt).toLocaleString()}</span>
							<Button variant="ghost" size="sm" class="text-destructive" onClick={async () => { await revokeInvite(i.id); await reload(); }}>Revoke</Button>
						</li>
					))}
				</ul>
			)}
			{used.length > 0 && <Hint class="text-xs">Used by: {used.map((i) => i.usedBy).join(", ")}</Hint>}
		</Section>
	);
}

function UsersSection() {
	const [users, setUsers] = useState<UserSummary[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	useEffect(() => void listUsers().then(setUsers, (e) => setError(errorMessage(e))), []);
	return (
		<Section title="Users">
			<ErrorText>{error}</ErrorText>
			{users && (
				<ul class="divide-y rounded-lg border">
					{users.map((x) => (
						<li key={x.id} class="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
							<span class="flex-1 font-medium">{x.username}</span>
							{x.role === "admin" && <Badge>admin</Badge>}
							{x.totpEnabled ? <Badge variant="secondary">2-step</Badge> : <Badge variant="warning">no 2-step</Badge>}
							<span class="text-muted-foreground text-xs">joined {timeAgo(x.createdAt)}</span>
						</li>
					))}
				</ul>
			)}
		</Section>
	);
}
