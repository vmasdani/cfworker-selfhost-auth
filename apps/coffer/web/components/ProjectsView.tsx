import { Badge, Button, Card, Field, Input } from "@cfsa/ui";
import { FolderKey, Plus } from "lucide-preact";
import { useState } from "preact/hooks";
import { createProject, type Project } from "../lib/projects.ts";
import { EmptyState, ErrorText, errorMessage, Hint } from "./common.tsx";

const ENV_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;

export function ProjectsView({ projects, reload, open }: { projects: Project[] | null; reload: () => Promise<void>; open: (id: string) => void }) {
	const [creating, setCreating] = useState(false);

	return (
		<div class="grid gap-6">
			<div class="flex flex-wrap items-center justify-between gap-3">
				<div>
					<h1 class="text-2xl font-semibold tracking-tight">Projects</h1>
					<p class="text-muted-foreground text-sm">Each project has environments; each environment has its own key and secrets.</p>
				</div>
				{!creating && <Button onClick={() => setCreating(true)}><Plus /> New project</Button>}
			</div>

			{creating && (
				<NewProject onCancel={() => setCreating(false)} onCreated={async (id) => {
					setCreating(false);
					await reload();
					open(id);
				}} />
			)}

			{projects === null ? (
				<Hint>Decrypting…</Hint>
			) : projects.length === 0 ? (
				!creating && (
					<EmptyState icon={<FolderKey />} title="No projects yet">
						Create a project, or ask a project owner to add you.
					</EmptyState>
				)
			) : (
				<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
					{projects.map((p) => (
						<button type="button" key={p.id} onClick={() => open(p.id)} class="text-left cursor-pointer">
							<Card class="hover:border-primary/50 h-full gap-3 px-5 py-4 transition-colors">
								<div class="flex items-start justify-between gap-2">
									<h2 class="truncate font-semibold">{p.name}</h2>
									<Badge variant={p.role === "owner" ? "default" : "secondary"}>{p.role}</Badge>
								</div>
								<div class="flex flex-wrap gap-1.5">
									{p.environments.map((e) => (
										<Badge variant="outline" key={e.id}>{e.name} · {e.secretCount}</Badge>
									))}
								</div>
							</Card>
						</button>
					))}
				</div>
			)}
		</div>
	);
}

function NewProject({ onCancel, onCreated }: { onCancel: () => void; onCreated: (id: string) => Promise<void> }) {
	const [name, setName] = useState("");
	const [envs, setEnvs] = useState("dev, staging, prod");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function submit(e: Event) {
		e.preventDefault();
		const list = envs.split(/[\s,]+/).filter(Boolean);
		if (!name.trim()) return setError("Enter a project name");
		if (!list.length) return setError("Add at least one environment");
		const bad = list.find((n) => !ENV_NAME.test(n));
		if (bad) return setError(`"${bad}": environment names use letters, digits, ".", "_" or "-"`);
		if (new Set(list.map((n) => n.toLowerCase())).size !== list.length) return setError("Environment names must be unique");
		setBusy(true);
		setError(null);
		try {
			await onCreated(await createProject(name.trim(), list));
		} catch (err) {
			setError(errorMessage(err));
			setBusy(false);
		}
	}

	return (
		<Card class="px-5">
			<form class="grid gap-4 sm:grid-cols-2" onSubmit={submit}>
				<Field label="Project name" htmlFor="np-name">
					<Input id="np-name" value={name} maxLength={64} autofocus placeholder="e.g. Shop backend" onInput={(e) => setName(e.currentTarget.value)} />
				</Field>
				<Field label="Environments" htmlFor="np-envs" hint="Comma-separated. You can add more later.">
					<Input id="np-envs" value={envs} onInput={(e) => setEnvs(e.currentTarget.value)} />
				</Field>
				<div class="sm:col-span-2 grid gap-3">
					<ErrorText>{error}</ErrorText>
					<div class="flex justify-end gap-2">
						<Button variant="outline" onClick={onCancel}>Cancel</Button>
						<Button type="submit" disabled={busy}>{busy ? "Creating…" : "Create project"}</Button>
					</div>
				</div>
			</form>
		</Card>
	);
}
