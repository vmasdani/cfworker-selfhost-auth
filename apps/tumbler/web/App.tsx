import { useCallback, useEffect, useState } from "preact/hooks";
import { Codes } from "./components/Codes.tsx";
import { EntryForm } from "./components/EntryForm.tsx";
import { ExportView } from "./components/ExportView.tsx";
import { ImportView } from "./components/ImportView.tsx";
import { SettingsView } from "./components/SettingsView.tsx";
import { Setup } from "./components/Setup.tsx";
import { Unlock } from "./components/Unlock.tsx";
import type { Entry } from "./lib/entries.ts";
import { syncNow } from "./lib/account.ts";
import * as vault from "./lib/vault.ts";

type Status = "loading" | "setup" | "locked" | "unlocked";
type View =
	| { name: "list" }
	| { name: "add" }
	| { name: "edit"; entry: Entry }
	| { name: "settings" }
	| { name: "import"; initialUri?: string }
	| { name: "export" };

/** Lock when the app has been in the background longer than this. */
const HIDDEN_LOCK_MS = 60_000;

export function App() {
	const [status, setStatus] = useState<Status>("loading");
	const [hasPin, setHasPin] = useState(false);
	const [view, setView] = useState<View>({ name: "list" });
	const [settings, setSettings] = useState<vault.Settings>(vault.DEFAULT_SETTINGS);
	const [invite, setInvite] = useState<string | undefined>(readInviteFromHash);

	const refreshState = useCallback(async () => {
		const s = await vault.vaultState();
		setHasPin(s.hasPin);
		return s;
	}, []);

	useEffect(() => {
		void (async () => {
			const s = await refreshState();
			setSettings(await vault.getSettings());
			setStatus(s.exists ? "locked" : "setup");
		})();
	}, [refreshState]);

	const doLock = useCallback(() => {
		vault.lock();
		setView({ name: "list" });
		setStatus("locked");
		void refreshState();
	}, [refreshState]);

	useAutoLock(status === "unlocked", settings.autoLockMinutes, doLock);
	useAutoSync(status === "unlocked");

	// An invite link opened while a vault exists goes to Settings → Sync.
	useEffect(() => {
		if (invite && status === "unlocked") setView({ name: "settings" });
	}, [invite, status]);

	if (status === "loading") return null;
	if (status === "setup") return <Setup invite={invite} onDone={() => { setInvite(undefined); void refreshState(); setStatus("unlocked"); }} />;
	if (status === "locked") {
		return <Unlock hasPin={hasPin} onUnlocked={() => setStatus("unlocked")} onPinStateChange={refreshState} />;
	}

	switch (view.name) {
		case "add":
			return (
				<EntryForm
					onDone={() => setView({ name: "list" })}
					onImportMigration={(uri) => setView({ name: "import", initialUri: uri })}
				/>
			);
		case "import":
			return <ImportView initialUri={view.initialUri} onDone={() => setView({ name: "list" })} />;
		case "export":
			return <ExportView onDone={() => setView({ name: "settings" })} />;
		case "edit":
			return <EntryForm entry={view.entry} onDone={() => setView({ name: "list" })} />;
		case "settings":
			return (
				<SettingsView
					settings={settings}
					hasPin={hasPin}
					onSettings={async (s) => { await vault.saveSettings(s); setSettings(s); }}
					onPinChanged={refreshState}
					onLock={doLock}
					onImport={() => setView({ name: "import" })}
					onExport={() => setView({ name: "export" })}
					onBack={() => { setInvite(undefined); setView({ name: "list" }); }}
					invite={invite}
				/>
			);
		default:
			return (
				<Codes
					settings={settings}
					onAdd={() => setView({ name: "add" })}
					onEdit={(entry) => setView({ name: "edit", entry })}
					onSettings={() => setView({ name: "settings" })}
					onLock={doLock}
				/>
			);
	}
}

/** Reads and removes "#invite=<token>" so the token does not linger in the address bar or history. */
function readInviteFromHash(): string | undefined {
	const m = /^#invite=([A-Za-z0-9_-]{20,})$/.exec(location.hash);
	if (!m) return undefined;
	history.replaceState(null, "", location.pathname + location.search);
	return m[1];
}

/** Sync on unlock, shortly after local edits, when coming back online, and every 5 minutes. */
function useAutoSync(active: boolean) {
	useEffect(() => {
		if (!active) return;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const soon = () => {
			clearTimeout(timer);
			timer = setTimeout(() => void syncNow(), 1500);
		};
		const now = () => void syncNow();
		void syncNow();
		vault.vaultEvents.addEventListener("change", soon);
		window.addEventListener("online", now);
		const visible = () => { if (!document.hidden) now(); };
		document.addEventListener("visibilitychange", visible);
		const interval = setInterval(now, 5 * 60_000);
		return () => {
			clearTimeout(timer);
			clearInterval(interval);
			vault.vaultEvents.removeEventListener("change", soon);
			window.removeEventListener("online", now);
			document.removeEventListener("visibilitychange", visible);
		};
	}, [active]);
}

function useAutoLock(active: boolean, minutes: number, lock: () => void) {
	useEffect(() => {
		if (!active) return;
		let last = Date.now();
		let hiddenAt: number | null = null;
		const bump = () => { last = Date.now(); };
		const check = () => { if (Date.now() - last > minutes * 60_000) lock(); };
		const onVisibility = () => {
			if (document.hidden) {
				hiddenAt = Date.now();
				return;
			}
			if (hiddenAt !== null && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lock();
			else check();
			hiddenAt = null;
		};
		const events = ["pointerdown", "keydown", "scroll", "touchstart"] as const;
		for (const e of events) window.addEventListener(e, bump, { passive: true });
		document.addEventListener("visibilitychange", onVisibility);
		const timer = setInterval(check, 5_000);
		return () => {
			for (const e of events) window.removeEventListener(e, bump);
			document.removeEventListener("visibilitychange", onVisibility);
			clearInterval(timer);
		};
	}, [active, minutes, lock]);
}
