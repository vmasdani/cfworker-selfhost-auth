import { Badge, Button, Field, Input, Tabs } from "@cfsa/ui";
import { Plus, Trash2 } from "lucide-preact";
import { useState } from "preact/hooks";
import {
	addEnvironment,
	deleteEnvironment,
	deleteProject,
	renameEnvironment,
	renameProject,
	type Environment,
	type Project,
} from "../lib/projects.ts";
import { AccessTab } from "./AccessTab.tsx";
import { ErrorText, errorMessage, Hint, Section, toast } from "./common.tsx";
import { IntegrateTab } from "./IntegrateTab.tsx";
import { SecretsTab } from "./SecretsTab.tsx";

export type ProjectTab = "secrets" | "access" | "integrate" | "settings";

export function ProjectView({ project, tab, setTab, reload, onDeleted }: {
	project: Project;
	tab: ProjectTab;
	setTab: (t: ProjectTab) => void;
	reload: () => Promise<void>;
	onDeleted: () => void;
}) {
	const [envId, setEnvId] = useState(project.environments[0]!.id);
	const items: { value: ProjectTab; label: string }[] = [
		{ value: "secrets", label: "Secrets" },
		{ value: "access", label: "Access" },
		{ value: "integrate", label: "Integrate" },
		...(project.role === "owner" ? [{ value: "settings" as const, label: "Settings" }] : []),
	];

	return (
		<div class="grid gap-5">
			<div class="flex flex-wrap items-center gap-3">
				<h1 class="break-anywhere text-2xl font-semibold tracking-tight">{project.name}</h1>
				<Badge variant={project.role === "owner" ? "default" : "secondary"}>{project.role}</Badge>
			</div>
			<div class="max-w-xl"><Tabs value={tab} onChange={setTab} items={items} /></div>
			{tab === "secrets" && <SecretsTab project={project} envId={envId} setEnvId={setEnvId} onChanged={() => void reload()} />}
			{tab === "access" && <AccessTab project={project} onLeft={onDeleted} />}
			{tab === "integrate" && <IntegrateTab />}
			{tab === "settings" && project.role === "owner" && <SettingsTab project={project} reload={reload} onDeleted={onDeleted} />}
		</div>
	);
}

function SettingsTab({ project, reload, onDeleted }: { project: Project; reload: () => Promise<void>; onDeleted: () => void }) {
	const [name, setName] = useState(project.name);
	const [newEnv, setNewEnv] = useState("");
	const [confirmName, setConfirmName] = useState("");
	const [error, setError] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);

	async function run(fn: () => Promise<unknown>, done: string) {
		setBusy(true);
		setError(null);
		try {
			await fn();
			toast(done);
			await reload();
		} catch (e) {
			setError(errorMessage(e));
		} finally {
			setBusy(false);
		}
	}

	return (
		<div class="grid gap-8">
			<ErrorText>{error}</ErrorText>
			<Section title="Project name">
				<form class="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); void run(() => renameProject(project, name.trim()), "Renamed"); }}>
					<Field label="Name" htmlFor="ps-name" class="min-w-56 flex-1">
						<Input id="ps-name" value={name} maxLength={64} onInput={(e) => setName(e.currentTarget.value)} />
					</Field>
					<Button type="submit" disabled={busy || !name.trim() || name.trim() === project.name}>Save</Button>
				</form>
			</Section>

			<Section title="Environments" description="Each environment has its own key. Client IDs are bound to one environment.">
				<ul class="divide-y rounded-md border">
					{project.environments.map((e) => (
						<EnvRow key={e.id} env={e} canDelete={project.environments.length > 1} busy={busy} run={run} />
					))}
				</ul>
				<form class="flex flex-wrap items-end gap-2" onSubmit={(e) => {
					e.preventDefault();
					void run(() => addEnvironment(project, newEnv.trim()), `Added ${newEnv.trim()}`).then(() => setNewEnv(""));
				}}>
					<Field label="New environment" htmlFor="ps-env" class="min-w-56 flex-1">
						<Input id="ps-env" value={newEnv} maxLength={32} placeholder="e.g. preview" onInput={(e) => setNewEnv(e.currentTarget.value)} />
					</Field>
					<Button type="submit" variant="outline" disabled={busy || !newEnv.trim()}><Plus /> Add</Button>
				</form>
			</Section>

			<Section title="Delete project" description="Deletes all environments, secrets, history, members and client IDs. This cannot be undone.">
				<Field label={<>Type <span class="font-mono">{project.name}</span> to confirm</>} htmlFor="ps-del">
					<Input id="ps-del" value={confirmName} onInput={(e) => setConfirmName(e.currentTarget.value)} />
				</Field>
				<Button variant="destructive" disabled={busy || confirmName !== project.name}
					onClick={() => void run(() => deleteProject(project), `Deleted ${project.name}`).then(onDeleted)}>
					<Trash2 /> Delete project
				</Button>
			</Section>
		</div>
	);
}

function EnvRow({ env, canDelete, busy, run }: {
	env: Environment;
	canDelete: boolean;
	busy: boolean;
	run: (fn: () => Promise<unknown>, done: string) => Promise<void>;
}) {
	const [name, setName] = useState(env.name);
	return (
		<li class="flex flex-wrap items-center gap-2 px-3 py-2">
			<Input aria-label={`Name of ${env.name}`} class="h-8 max-w-56" value={name} maxLength={32} onInput={(e) => setName(e.currentTarget.value)} />
			<Hint class="flex-1 text-xs">{env.secretCount} secret(s)</Hint>
			{name.trim() !== env.name && (
				<Button size="sm" variant="outline" disabled={busy} onClick={() => void run(() => renameEnvironment(env, name.trim()), "Renamed")}>Save</Button>
			)}
			<Button size="sm" variant="destructive-outline" disabled={busy || !canDelete}
				title={canDelete ? undefined : "A project needs at least one environment"}
				onClick={() => {
					if (!confirm(`Delete ${env.name}, its ${env.secretCount} secret(s) and its client IDs? This cannot be undone.`)) return;
					void run(() => deleteEnvironment(env), `Deleted ${env.name}`);
				}}>
				Delete
			</Button>
		</li>
	);
}
