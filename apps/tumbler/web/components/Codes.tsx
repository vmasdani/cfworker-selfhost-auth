import { totpRemainingMs } from "@cfsa/totp";
import { useEffect, useState } from "preact/hooks";
import { copySecret } from "../lib/clipboard.ts";
import { matchesQuery, type Entry } from "../lib/entries.ts";
import { codeFor, entryCounter, formatCode } from "../lib/otp-keys.ts";
import { listEntries, saveEntries, type Settings } from "../lib/vault.ts";
import { Avatar, Timer, TopBar, useNow, useToast } from "./ui.tsx";

interface Props {
	settings: Settings;
	onAdd: () => void;
	onEdit: (e: Entry) => void;
	onSettings: () => void;
	onLock: () => void;
}

export function Codes({ settings, onAdd, onEdit, onSettings, onLock }: Props) {
	const [entries, setEntries] = useState<Entry[] | null>(null);
	const [query, setQuery] = useState("");
	const [toast, showToast] = useToast();
	const now = useNow();

	const reload = () => listEntries().then(setEntries);
	useEffect(() => { void reload(); }, []);

	async function copy(code: string) {
		try {
			await copySecret(code, settings.clipboardClearSeconds);
			showToast(settings.clipboardClearSeconds > 0 ? `Copied. Clears in ${settings.clipboardClearSeconds}s` : "Copied");
		} catch {
			showToast("Copy failed");
		}
	}

	async function nextHotp(e: Entry) {
		await saveEntries([{ ...e, counter: e.counter + 1, updatedAt: Date.now() }]);
		await reload();
	}

	const visible = entries?.filter((e) => matchesQuery(e, query)) ?? [];

	return (
		<div class="shell">
			<TopBar title="Tumbler">
				<button class="icon" onClick={onLock} aria-label="Lock" title="Lock">🔒</button>
				<button class="icon" onClick={onSettings} aria-label="Settings" title="Settings">⚙</button>
			</TopBar>

			{entries && entries.length > 0 && (
				<input class="search" type="search" placeholder="Search" value={query}
					onInput={(e) => setQuery(e.currentTarget.value)} aria-label="Search" />
			)}

			{entries && entries.length === 0 && (
				<div class="empty">
					<img src="/icon.svg" alt="" />
					<p>No accounts yet.</p>
					<button class="primary" onClick={onAdd}>Add account</button>
				</div>
			)}

			<div class="list">
				{visible.map((e) => (
					<EntryCard key={e.id} entry={e} now={now} onCopy={copy} onEdit={() => onEdit(e)} onNext={() => nextHotp(e)} />
				))}
			</div>
			{entries && entries.length > 0 && visible.length === 0 && <p class="empty">No matches.</p>}

			<button class="fab" onClick={onAdd} aria-label="Add account" title="Add account">+</button>
			{toast && <div class="toast" role="status">{toast}</div>}
		</div>
	);
}

interface CardProps {
	entry: Entry;
	now: number;
	onCopy: (code: string) => void;
	onEdit: () => void;
	onNext: () => void;
}

function EntryCard({ entry, now, onCopy, onEdit, onNext }: CardProps) {
	const [code, setCode] = useState("");
	const counter = entryCounter(entry, now);

	useEffect(() => {
		let alive = true;
		codeFor(entry, counter).then((c) => alive && setCode(c), () => alive && setCode("error"));
		return () => { alive = false; };
	}, [entry.id, entry.secret, entry.algorithm, entry.digits, counter]);

	const isTotp = entry.type === "totp";
	const remaining = isTotp ? totpRemainingMs(now, entry.period) : 0;
	const expiring = isTotp && remaining <= 5000;
	const title = entry.issuer || entry.account || "Unnamed";

	return (
		<div class="entry" role="button" tabIndex={0}
			onClick={() => code && onCopy(code)}
			onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (code) onCopy(code); } }}
			onContextMenu={(e) => { e.preventDefault(); onEdit(); }}
			aria-label={`${title}, code ${code.split("").join(" ")}. Tap to copy.`}>
			<Avatar name={title} />
			<div class="meta">
				<div class="issuer">{title}</div>
				{entry.issuer && entry.account && <div class="account">{entry.account}</div>}
				<div class={`code${expiring ? " expiring" : ""}`}>{code ? formatCode(code) : "··· ···"}</div>
			</div>
			<div class="side">
				{isTotp ? (
					<Timer remainingMs={remaining} periodMs={entry.period * 1000} />
				) : (
					<button class="icon" title="Next code" aria-label="Next code"
						onClick={(e) => { e.stopPropagation(); onNext(); }}>↻</button>
				)}
				<button class="icon" title="Edit" aria-label="Edit" onClick={(e) => { e.stopPropagation(); onEdit(); }}>⋯</button>
			</div>
		</div>
	);
}
