import { Alert, Badge, Button, Checkbox, Field, Input, Select } from "@cfsa/ui";
import { Bot, ShieldCheck, TriangleAlert, UserPlus, Users } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import type { MachineCredentials } from "../lib/keys.ts";
import { fingerprint } from "../lib/keys.ts";
import {
	addMember,
	createIdentity,
	listIdentities,
	listMembers,
	removeMember,
	revokeIdentity,
	setMemberRole,
	type MachineIdentity,
	type Member,
	type Project,
	type Role,
} from "../lib/projects.ts";
import { unlocked } from "../lib/session.ts";
import { CopyButton, EmptyState, ErrorText, errorMessage, Hint, Section, timeAgo, toast } from "./common.tsx";

export function credentialsEnv(c: MachineCredentials): string {
	return `COFFER_URL=${location.origin}\nCOFFER_CLIENT_ID=${c.clientId}\nCOFFER_CLIENT_SECRET=${c.clientSecret}\n`;
}

export function AccessTab({ project, onLeft }: { project: Project; onLeft: () => void }) {
	return (
		<div class="grid gap-8">
			<MachineSection project={project} />
			<MembersSection project={project} onLeft={onLeft} />
		</div>
	);
}

// --- machine identities ------------------------------------------------------------------------------

function MachineSection({ project }: { project: Project }) {
	const owner = project.role === "owner";
	const [items, setItems] = useState<MachineIdentity[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [name, setName] = useState("");
	const [envId, setEnvId] = useState(project.environments[0]!.id);
	const [scope, setScope] = useState<"read" | "write">("read");
	const [busy, setBusy] = useState(false);
	const [created, setCreated] = useState<{ creds: MachineCredentials; env: string; scope: string } | null>(null);

	const load = () => listIdentities(project).then(setItems, (e) => setError(errorMessage(e)));
	useEffect(() => void load(), [project.id]);

	async function create(e: Event) {
		e.preventDefault();
		const env = project.environments.find((x) => x.id === envId)!;
		setBusy(true);
		setError(null);
		try {
			const creds = await createIdentity(project, env, name.trim(), scope);
			setCreated({ creds, env: env.name, scope });
			setName("");
			await load();
		} catch (err) {
			setError(errorMessage(err));
		} finally {
			setBusy(false);
		}
	}

	async function revoke(m: MachineIdentity) {
		if (!confirm(`Revoke "${m.name}"? Apps using ${m.id} lose access immediately.`)) return;
		try {
			await revokeIdentity(m.id);
			toast(`Revoked ${m.name}`);
			await load();
		} catch (err) {
			setError(errorMessage(err));
		}
	}

	const envName = (id: string) => project.environments.find((e) => e.id === id)?.name ?? "?";

	return (
		<Section title="Client IDs" description="Credentials for apps and CI. Each client ID reads (and optionally writes) one environment through the REST API.">
			{created ? (
				<CreatedCredentials {...created} onDone={() => setCreated(null)} />
			) : owner ? (
				<form class="grid items-end gap-3 sm:grid-cols-[1fr_auto_auto_auto]" onSubmit={create}>
					<Field label="Name" htmlFor="mi-name">
						<Input id="mi-name" value={name} maxLength={64} placeholder="e.g. api-server, github-actions" onInput={(e) => setName(e.currentTarget.value)} />
					</Field>
					<Field label="Environment" htmlFor="mi-env">
						<Select id="mi-env" value={envId} onChange={(e) => setEnvId(e.currentTarget.value)}>
							{project.environments.map((e) => <option value={e.id}>{e.name}</option>)}
						</Select>
					</Field>
					<Field label="Access" htmlFor="mi-scope">
						<Select id="mi-scope" value={scope} onChange={(e) => setScope(e.currentTarget.value as "read" | "write")}>
							<option value="read">Read only</option>
							<option value="write">Read and write</option>
						</Select>
					</Field>
					<Button type="submit" disabled={busy || !name.trim()}><Bot /> {busy ? "Creating…" : "Create"}</Button>
				</form>
			) : (
				<Hint>Only project owners can create client IDs.</Hint>
			)}
			<ErrorText>{error}</ErrorText>
			{items && items.length === 0 && !created && <EmptyState icon={<Bot />} title="No client IDs yet" />}
			{items && items.length > 0 && (
				<ul class="divide-y rounded-md border">
					{items.map((m) => (
						<li key={m.id} class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5">
							<div class="grid min-w-0 flex-1 gap-0.5">
								<div class="flex flex-wrap items-center gap-2">
									<span class="font-medium">{m.name}</span>
									<Badge variant="outline">{envName(m.envId)}</Badge>
									<Badge variant={m.scope === "write" ? "warning" : "secondary"}>{m.scope === "write" ? "read & write" : "read only"}</Badge>
								</div>
								<code class="text-muted-foreground break-anywhere font-mono text-xs">{m.id}</code>
								<span class="text-muted-foreground text-xs">
									Last used {timeAgo(m.lastUsedAt)} · created {timeAgo(m.createdAt)}{m.createdBy ? ` by ${m.createdBy}` : ""}
								</span>
							</div>
							{owner && <Button variant="destructive-outline" size="sm" onClick={() => revoke(m)}>Revoke</Button>}
						</li>
					))}
				</ul>
			)}
		</Section>
	);
}

function CreatedCredentials({ creds, env, scope, onDone }: { creds: MachineCredentials; env: string; scope: string; onDone: () => void }) {
	const [saved, setSaved] = useState(false);
	const text = credentialsEnv(creds);
	return (
		<div class="grid gap-3">
			<Alert variant="warning" icon={<TriangleAlert />} title="Copy the client secret now. It is shown only once.">
				<p>
					The server never had it, so it cannot be shown again. Put these lines in your app's secret store (.env file, CI
					secrets, Worker secrets…). Lost it? Revoke this client ID and create a new one.
				</p>
			</Alert>
			<p class="text-sm">
				<span class="font-medium">{env}</span> · {scope === "write" ? "read & write" : "read only"}
			</p>
			<pre class="bg-muted break-anywhere rounded-lg border border-dashed px-4 py-3 font-mono text-xs whitespace-pre-wrap" aria-label="Client credentials">{text}</pre>
			<CopyButton value={text} label="Copy .env lines" />
			<Checkbox checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)}>I stored the client secret</Checkbox>
			<Button disabled={!saved} onClick={onDone}>Done</Button>
		</div>
	);
}

// --- members -------------------------------------------------------------------------------------------

function MembersSection({ project, onLeft }: { project: Project; onLeft: () => void }) {
	const me = unlocked()!.me;
	const owner = project.role === "owner";
	const [members, setMembers] = useState<Member[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [username, setUsername] = useState("");
	const [role, setRole] = useState<Role>("member");
	const [busy, setBusy] = useState(false);
	const [added, setAdded] = useState<{ username: string; fp: string } | null>(null);

	const load = () => listMembers(project).then(setMembers, (e) => setError(errorMessage(e)));
	useEffect(() => void load(), [project.id]);

	async function add(e: Event) {
		e.preventDefault();
		setBusy(true);
		setError(null);
		try {
			const pub = await addMember(project, username, role);
			setAdded({ username: username.trim().toLowerCase(), fp: await fingerprint(pub) });
			setUsername("");
			await load();
		} catch (err) {
			setError(errorMessage(err));
		} finally {
			setBusy(false);
		}
	}

	async function act(fn: () => Promise<unknown>, done: string) {
		setError(null);
		try {
			await fn();
			toast(done);
			await load();
		} catch (err) {
			setError(errorMessage(err));
		}
	}

	return (
		<Section title="Members" description="People who can read and edit this project's secrets in the dashboard. Owners also manage members, client IDs and environments.">
			{owner && (
				<form class="grid items-end gap-3 sm:grid-cols-[1fr_auto_auto]" onSubmit={add}>
					<Field label="Username" htmlFor="mb-user">
						<Input id="mb-user" value={username} autocapitalize="none" spellcheck={false} placeholder="They must have signed in once"
							onInput={(e) => setUsername(e.currentTarget.value)} />
					</Field>
					<Field label="Role" htmlFor="mb-role">
						<Select id="mb-role" value={role} onChange={(e) => setRole(e.currentTarget.value as Role)}>
							<option value="member">Member</option>
							<option value="owner">Owner</option>
						</Select>
					</Field>
					<Button type="submit" disabled={busy || !username.trim()}><UserPlus /> {busy ? "Adding…" : "Add"}</Button>
				</form>
			)}
			{added && (
				<Alert variant="success" icon={<ShieldCheck />} title={`Added ${added.username}`}>
					The project key was encrypted to their key with fingerprint <code class="font-mono">{added.fp}</code>. To rule out a
					tampered server, ask them to confirm it matches the one under Account → Your key.
				</Alert>
			)}
			<ErrorText>{error}</ErrorText>
			{members?.length === 0 && <EmptyState icon={<Users />} title="No members" />}
			{members && members.length > 0 && (
				<ul class="divide-y rounded-md border">
					{members.map((m) => (
						<li key={m.userId} class="flex flex-wrap items-center gap-2 px-3 py-2.5">
							<span class="flex-1 font-medium">{m.username}{m.userId === me.id && <span class="text-muted-foreground font-normal"> (you)</span>}</span>
							{owner && m.userId !== me.id ? (
								<Select aria-label={`Role of ${m.username}`} class="h-8 w-28" value={m.role}
									onChange={(e) => act(() => setMemberRole(project, m.userId, e.currentTarget.value as Role), `${m.username} is now ${e.currentTarget.value}`)}>
									<option value="member">member</option>
									<option value="owner">owner</option>
								</Select>
							) : (
								<Badge variant={m.role === "owner" ? "default" : "secondary"}>{m.role}</Badge>
							)}
							{(owner || m.userId === me.id) && (
								<Button variant="destructive-outline" size="sm" onClick={() => {
									const self = m.userId === me.id;
									if (!confirm(self ? `Leave ${project.name}?` : `Remove ${m.username} from ${project.name}?`)) return;
									void act(() => removeMember(project, m.userId), self ? `Left ${project.name}` : `Removed ${m.username}`).then(() => self && onLeft());
								}}>
									{m.userId === me.id ? "Leave" : "Remove"}
								</Button>
							)}
						</li>
					))}
				</ul>
			)}
			{owner && (
				<Hint class="text-xs">
					Removing someone stops them fetching secrets, but keys are not rotated: if they copied secrets or keys before, rotate
					those secrets.
				</Hint>
			)}
		</Section>
	);
}
