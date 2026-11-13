import { totpRemainingMs } from "@cfsa/totp";
import { Lock, Pencil, Plus, RotateCw, Search, Settings as SettingsIcon } from "lucide-preact";
import { useEffect, useState } from "preact/hooks";
import { copySecret } from "../lib/clipboard.ts";
import { matchesQuery, type Entry } from "../lib/entries.ts";
import { codeFor, entryCounter, formatCode } from "../lib/otp-keys.ts";
import { listEntries, saveEntries, vaultEvents, type Settings } from "../lib/vault.ts";
import { Avatar, Page, Timer, toast, useNow } from "./common.tsx";
import { Button, cn, Input } from "./ui/index.tsx";

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
	const now = useNow();

	const reload = () => listEntries().then(setEntries);
	useEffect(() => {
		void reload();
		const onRemote = () => void reload();
		vaultEvents.addEventListener("remote", onRemote);
		return () => vaultEvents.removeEventListener("remote", onRemote);
	}, []);

	async function copy(code: string, which = "") {
		try {
			await copySecret(code, settings.clipboardClearSeconds);
			const clears = settings.clipboardClearSeconds > 0 ? `. Clears in ${settings.clipboardClearSeconds}s` : "";
			toast(`Copied${which}${clears}`);
		} catch {
			toast("Copy failed");
		}
	}

	async function advanceHotp(e: Entry) {
		await saveEntries([{ ...e, counter: e.counter + 1, updatedAt: Date.now() }]);
		await reload();
	}

	const visible = entries?.filter((e) => matchesQuery(e, query)) ?? [];

	return (
		<Page
			title="Tumbler"
			actions={
				<>
					<Button variant="ghost" size="icon" onClick={onLock} aria-label="Lock" title="Lock"><Lock /></Button>
					<Button variant="ghost" size="icon" onClick={onSettings} aria-label="Settings" title="Settings"><SettingsIcon /></Button>
				</>
			}
		>
			{entries && entries.length > 0 && (
				<div class="relative mb-3">
					<Search class="text-muted-foreground pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
					<Input type="search" placeholder="Search" value={query} class="pl-9"
						onInput={(e) => setQuery(e.currentTarget.value)} aria-label="Search" />
				</div>
			)}

			{entries && entries.length === 0 && (
				<div class="flex flex-col items-center gap-4 py-16 text-center">
					<img src="/icon.svg" alt="" class="size-16 opacity-90" />
					<div class="grid gap-1">
						<p class="font-medium">No accounts yet</p>
						<p class="text-muted-foreground text-sm">Scan a QR code, enter a key, or import from another app.</p>
					</div>
					<Button onClick={onAdd}><Plus /> Add account</Button>
				</div>
			)}

			<div class="grid gap-2.5">
				{visible.map((e) => (
					<EntryCard key={e.id} entry={e} now={now} showNext={settings.showNextCode}
						onCopy={copy} onEdit={() => onEdit(e)} onAdvance={() => advanceHotp(e)} />
				))}
			</div>
			{entries && entries.length > 0 && visible.length === 0 && (
				<p class="text-muted-foreground py-10 text-center text-sm">No matches.</p>
			)}

			<Button onClick={onAdd} aria-label="Add account" title="Add account"
				class="fixed right-[max(1rem,calc(50vw-17rem))] bottom-6 z-20 size-14 rounded-2xl shadow-lg [&_svg:not([class*='size-'])]:size-6">
				<Plus />
			</Button>
		</Page>
	);
}

interface CardProps {
	entry: Entry;
	now: number;
	showNext: boolean;
	onCopy: (code: string, which?: string) => void;
	onEdit: () => void;
	onAdvance: () => void;
}

function useCode(entry: Entry, counter: number, enabled = true): string {
	const [code, setCode] = useState("");
	useEffect(() => {
		if (!enabled) return;
		let alive = true;
		codeFor(entry, counter).then((c) => alive && setCode(c), () => alive && setCode("error"));
		return () => { alive = false; };
	}, [entry.id, entry.secret, entry.algorithm, entry.digits, counter, enabled]);
	return code;
}

function EntryCard({ entry, now, showNext, onCopy, onEdit, onAdvance }: CardProps) {
	const isTotp = entry.type === "totp";
	const counter = entryCounter(entry, now);
	const code = useCode(entry, counter);
	const next = useCode(entry, counter + 1, isTotp && showNext);
	const remaining = isTotp ? totpRemainingMs(now, entry.period) : 0;
	const expiring = isTotp && remaining <= 5000;
	const title = entry.issuer || entry.account || "Unnamed";

	return (
		<div
			class="entry bg-card text-card-foreground hover:bg-accent/40 grid cursor-pointer grid-cols-[auto_1fr_auto] items-center gap-3 rounded-xl border p-3.5 shadow-xs transition-colors select-none active:scale-[0.99]"
			role="button"
			tabIndex={0}
			onClick={() => code && onCopy(code)}
			onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); if (code) onCopy(code); } }}
			onContextMenu={(e) => { e.preventDefault(); onEdit(); }}
			aria-label={`${title}, code ${code.split("").join(" ")}. Tap to copy.`}
		>
			<Avatar name={title} />
			<div class="min-w-0">
				<div class="issuer truncate font-medium">{title}</div>
				{entry.issuer && entry.account && <div class="account text-muted-foreground truncate text-xs">{entry.account}</div>}
				<div class={cn("code mt-1 font-mono text-[1.65rem] leading-none font-semibold tracking-wide tabular-nums", expiring ? "text-warning" : "text-primary")}>
					{code ? formatCode(code) : "··· ···"}
				</div>
				{isTotp && showNext && next && (
					<button
						type="button"
						class="next-code text-muted-foreground hover:text-foreground mt-1.5 inline-flex items-center gap-1.5 text-xs tabular-nums cursor-pointer"
						aria-label={`Next code ${next.split("").join(" ")}. Tap to copy.`}
						onClick={(e) => { e.stopPropagation(); onCopy(next, " next code"); }}
					>
						<span class="uppercase tracking-wider text-[10px]">Next</span>
						<span class="font-mono text-sm">{formatCode(next)}</span>
					</button>
				)}
			</div>
			<div class="flex flex-col items-center gap-1">
				{isTotp ? (
					<Timer remainingMs={remaining} periodMs={entry.period * 1000} />
				) : (
					<Button variant="ghost" size="icon" class="size-8" title="Advance counter" aria-label="Advance counter"
						onClick={(e) => { e.stopPropagation(); onAdvance(); }}>
						<RotateCw />
					</Button>
				)}
				<Button variant="ghost" size="icon" class="size-8" title="Edit" aria-label="Edit"
					onClick={(e) => { e.stopPropagation(); onEdit(); }}>
					<Pencil />
				</Button>
			</div>
		</div>
	);
}
