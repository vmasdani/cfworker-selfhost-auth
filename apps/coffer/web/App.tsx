import { Button, cn } from "@cfsa/ui";
import { FolderKey, Lock, UserRound } from "lucide-preact";
import type { ComponentChildren } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";
import { AccountView } from "./components/AccountView.tsx";
import { SignedOut, UnlockView } from "./components/AuthViews.tsx";
import { ErrorText, errorMessage, Logo, Toaster } from "./components/common.tsx";
import { ProjectsView } from "./components/ProjectsView.tsx";
import { ProjectView, type ProjectTab } from "./components/ProjectView.tsx";
import type { AccountResponse } from "./lib/api.ts";
import { loadProjects, type Project } from "./lib/projects.ts";
import { lock, serverSession, sessionEvents, unlocked } from "./lib/session.ts";

const AUTO_LOCK_MS = 15 * 60_000;

export type Route = { view: "projects" } | { view: "project"; id: string; tab: ProjectTab } | { view: "account" };

function readInvite(): string | undefined {
	return /#invite=([A-Za-z0-9_-]+)/.exec(location.hash)?.[1];
}

export function App() {
	const [, setTick] = useState(0);
	const [boot, setBoot] = useState<{ loading: boolean; account: AccountResponse | null; error?: string }>({ loading: true, account: null });

	const refresh = useCallback(() => {
		serverSession().then(
			(account) => setBoot({ loading: false, account }),
			(e) => setBoot({ loading: false, account: null, error: errorMessage(e) }),
		);
	}, []);

	useEffect(() => {
		const on = () => {
			setTick((t) => t + 1);
			// Locked: the server session may have been created after boot (sign-in), so look again.
			if (!unlocked()) {
				setBoot({ loading: true, account: null });
				refresh();
			}
		};
		sessionEvents.addEventListener("change", on);
		return () => sessionEvents.removeEventListener("change", on);
	}, [refresh]);

	useEffect(refresh, [refresh]);

	const u = unlocked();
	let screen: ComponentChildren;
	if (u) screen = <Dashboard key={u.me.id} />;
	else if (boot.loading) screen = <div class="text-muted-foreground grid min-h-dvh place-items-center text-sm">Loading…</div>;
	else if (boot.account && !readInvite()) screen = <UnlockView account={boot.account} />;
	else screen = (
		<>
			{boot.error && <div class="mx-auto max-w-sm px-4 pt-6"><ErrorText>{boot.error}</ErrorText></div>}
			<SignedOut invite={readInvite()} />
		</>
	);
	return (
		<>
			{screen}
			<Toaster />
		</>
	);
}

function useAutoLock() {
	useEffect(() => {
		let timer: ReturnType<typeof setTimeout>;
		const reset = () => {
			clearTimeout(timer);
			timer = setTimeout(lock, AUTO_LOCK_MS);
		};
		const events = ["pointerdown", "keydown", "scroll"] as const;
		for (const e of events) addEventListener(e, reset, { passive: true });
		reset();
		return () => {
			clearTimeout(timer);
			for (const e of events) removeEventListener(e, reset);
		};
	}, []);
}

function Dashboard() {
	const me = unlocked()!.me;
	const [route, setRoute] = useState<Route>({ view: "projects" });
	const [projects, setProjects] = useState<Project[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	useAutoLock();

	const reload = useCallback(async () => {
		try {
			setProjects(await loadProjects());
			setError(null);
		} catch (e) {
			setError(errorMessage(e));
		}
	}, []);
	useEffect(() => void reload(), [reload]);

	const project = route.view === "project" ? projects?.find((p) => p.id === route.id) : undefined;

	return (
		<div class="min-h-dvh">
			<header class="bg-background/85 supports-[backdrop-filter]:bg-background/70 sticky top-0 z-20 border-b backdrop-blur">
				<div class="mx-auto flex h-14 max-w-5xl items-center gap-1 px-4">
					<button type="button" class="mr-3 flex items-center gap-2 font-semibold tracking-tight cursor-pointer" onClick={() => setRoute({ view: "projects" })}>
						<Logo class="size-7" /> Coffer
					</button>
					<NavButton active={route.view !== "account"} onClick={() => setRoute({ view: "projects" })}><FolderKey /> <span class="max-sm:sr-only">Projects</span></NavButton>
					<NavButton active={route.view === "account"} onClick={() => setRoute({ view: "account" })}><UserRound /> <span class="max-sm:sr-only">{me.username}</span></NavButton>
					<div class="flex-1" />
					<Button variant="ghost" size="sm" onClick={lock} title="Lock (keys are dropped from memory)"><Lock /> Lock</Button>
				</div>
			</header>
			<main class="mx-auto max-w-5xl px-4 py-6 pb-24">
				<ErrorText>{error}</ErrorText>
				{route.view === "account" && <AccountView />}
				{route.view === "projects" && (
					<ProjectsView projects={projects} reload={reload} open={(id) => setRoute({ view: "project", id, tab: "secrets" })} />
				)}
				{route.view === "project" && project && (
					<ProjectView project={project} tab={route.tab} setTab={(tab) => setRoute({ view: "project", id: project.id, tab })}
						reload={reload} onDeleted={() => { setRoute({ view: "projects" }); void reload(); }} />
				)}
				{route.view === "project" && projects && !project && <ErrorText>This project no longer exists or you were removed from it.</ErrorText>}
			</main>
		</div>
	);
}

function NavButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: ComponentChildren }) {
	return (
		<Button variant="ghost" size="sm" onClick={onClick} class={cn(active && "bg-accent text-accent-foreground")} aria-current={active ? "page" : undefined}>
			{children}
		</Button>
	);
}
