import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";

export function Brand({ subtitle }: { subtitle?: string }) {
	return (
		<div class="brand">
			<img src="/icon.svg" alt="" />
			<h1>Tumbler Authenticator</h1>
			{subtitle && <p>{subtitle}</p>}
		</div>
	);
}

export function TopBar({ title, children, onBack }: { title: string; children?: ComponentChildren; onBack?: () => void }) {
	return (
		<header class="topbar">
			{onBack && (
				<button class="icon" onClick={onBack} aria-label="Back">←</button>
			)}
			<h1>
				{!onBack && <img src="/icon.svg" alt="" />}
				{title}
			</h1>
			{children}
		</header>
	);
}

/** Current time in ms, updated every second on the second boundary. */
export function useNow(): number {
	const [now, setNow] = useState(Date.now());
	useEffect(() => {
		let timer: ReturnType<typeof setTimeout>;
		const tick = () => {
			const t = Date.now();
			setNow(t);
			timer = setTimeout(tick, 1000 - (t % 1000) + 5);
		};
		tick();
		return () => clearTimeout(timer);
	}, []);
	return now;
}

export function useToast(): [string | null, (msg: string) => void] {
	const [msg, setMsg] = useState<string | null>(null);
	useEffect(() => {
		if (!msg) return;
		const t = setTimeout(() => setMsg(null), 1800);
		return () => clearTimeout(t);
	}, [msg]);
	return [msg, setMsg];
}

const PALETTE = ["#0ea5e9", "#8b5cf6", "#ec4899", "#f97316", "#14b8a6", "#6366f1", "#ef4444", "#84cc16", "#06b6d4", "#a855f7"];

export function Avatar({ name }: { name: string }) {
	let h = 0;
	for (const c of name.toLowerCase()) h = (h * 31 + c.charCodeAt(0)) >>> 0;
	const letter = [...name.trim()][0]?.toUpperCase() ?? "?";
	return <div class="avatar" style={{ background: PALETTE[h % PALETTE.length] }}>{letter}</div>;
}

export function Timer({ remainingMs, periodMs }: { remainingMs: number; periodMs: number }) {
	const r = 12;
	const c = 2 * Math.PI * r;
	const secs = Math.ceil(remainingMs / 1000);
	const offset = c * (1 - remainingMs / periodMs);
	return (
		<svg class={`timer${secs <= 5 ? " expiring" : ""}`} viewBox="0 0 30 30" aria-label={`${secs} seconds left`}>
			<circle class="track" cx="15" cy="15" r={r} />
			<circle class="bar" cx="15" cy="15" r={r} stroke-dasharray={c} stroke-dashoffset={offset}
				transform="rotate(-90 15 15)" stroke-linecap="round" />
			<text x="15" y="19" text-anchor="middle">{secs}</text>
		</svg>
	);
}
