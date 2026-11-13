import { useCallback, useEffect, useState } from "preact/hooks";
import { Codes } from "./components/Codes.tsx";
import { EntryForm } from "./components/EntryForm.tsx";
import { SettingsView } from "./components/SettingsView.tsx";
import { Setup } from "./components/Setup.tsx";
import { Unlock } from "./components/Unlock.tsx";
import type { Entry } from "./lib/entries.ts";
import * as vault from "./lib/vault.ts";

type Status = "loading" | "setup" | "locked" | "unlocked";
type View = { name: "list" } | { name: "add" } | { name: "edit"; entry: Entry } | { name: "settings" };

/** Lock when the app has been in the background longer than this. */
const HIDDEN_LOCK_MS = 60_000;

export function App() {
	const [status, setStatus] = useState<Status>("loading");
	const [hasPin, setHasPin] = useState(false);
	const [view, setView] = useState<View>({ name: "list" });
	const [settings, setSettings] = useState<vault.Settings>(vault.DEFAULT_SETTINGS);

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

	if (status === "loading") return null;
	if (status === "setup") return <Setup onDone={() => { void refreshState(); setStatus("unlocked"); }} />;
	if (status === "locked") {
		return <Unlock hasPin={hasPin} onUnlocked={() => setStatus("unlocked")} onPinStateChange={refreshState} />;
	}

	switch (view.name) {
		case "add":
			return <EntryForm onDone={() => setView({ name: "list" })} />;
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
					onBack={() => setView({ name: "list" })}
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
