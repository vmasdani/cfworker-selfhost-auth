import { ArrowLeft } from "lucide-preact";
import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { Button, Card, cn, inputClass } from "./ui/index.tsx";

export function Brand({ subtitle }: { subtitle?: string }) {
	return (
		<div class="flex flex-col items-center gap-2 text-center">
			<img src="/icon.svg" alt="" class="size-16" />
			<h1 class="text-xl font-semibold tracking-tight">Tumbler Authenticator</h1>
			{subtitle && <p class="text-muted-foreground text-sm">{subtitle}</p>}
		</div>
	);
}

/** Centered card for setup, unlock and other pre-app screens. */
export function AuthScreen({ subtitle, children }: { subtitle?: string; children: ComponentChildren }) {
	return (
		<div class="min-h-dvh grid place-items-center px-4 py-8">
			<Card class="w-full max-w-sm gap-6 px-6 py-7">
				<Brand subtitle={subtitle} />
				{children}
			</Card>
		</div>
	);
}

/** App page with a sticky top bar. */
export function Page({ title, onBack, actions, children }: {
	title: string;
	onBack?: () => void;
	actions?: ComponentChildren;
	children: ComponentChildren;
}) {
	return (
		<div class="mx-auto max-w-xl px-4 pb-28">
			<header class="bg-background/85 sticky top-0 z-10 -mx-4 mb-4 flex items-center gap-1 border-b px-2 py-2 backdrop-blur supports-[backdrop-filter]:bg-background/70">
				{onBack ? (
					<Button variant="ghost" size="icon" onClick={onBack} aria-label="Back">
						<ArrowLeft />
					</Button>
				) : (
					<img src="/icon.svg" alt="" class="ml-2 mr-1 size-7" />
				)}
				<h1 class="flex-1 truncate px-1 text-lg font-semibold tracking-tight">{title}</h1>
				{actions}
			</header>
			{children}
		</div>
	);
}

export function Section({ title, description, children }: { title: string; description?: ComponentChildren; children: ComponentChildren }) {
	return (
		<section class="mt-6 grid gap-3">
			<div class="grid gap-1 px-1">
				<h2 class="text-sm font-semibold tracking-tight">{title}</h2>
				{description && <p class="text-muted-foreground text-xs leading-relaxed">{description}</p>}
			</div>
			<Card class="gap-4 px-5 py-5">{children}</Card>
		</section>
	);
}

export const ErrorText = ({ children }: { children?: ComponentChildren }) =>
	children ? <p class="text-destructive text-sm" role="alert">{children}</p> : null;

export const Hint = ({ children, class: className }: { children?: ComponentChildren; class?: string }) =>
	children ? <p class={cn("text-muted-foreground text-sm leading-relaxed", className)}>{children}</p> : null;

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

// --- Toasts -----------------------------------------------------------------------------------------

const toastTarget = new EventTarget();

/** Show a short message at the bottom of the screen. */
export function toast(message: string): void {
	toastTarget.dispatchEvent(new CustomEvent("toast", { detail: message }));
}

export function Toaster() {
	const [msg, setMsg] = useState<{ text: string; id: number } | null>(null);
	useEffect(() => {
		const on = (e: Event) => setMsg({ text: (e as CustomEvent<string>).detail, id: Date.now() });
		toastTarget.addEventListener("toast", on);
		return () => toastTarget.removeEventListener("toast", on);
	}, []);
	useEffect(() => {
		if (!msg) return;
		const t = setTimeout(() => setMsg(null), 2000);
		return () => clearTimeout(t);
	}, [msg]);
	if (!msg) return null;
	return (
		<div class="pointer-events-none fixed inset-x-0 bottom-24 z-50 flex justify-center px-4">
			<div role="status" class="bg-popover text-popover-foreground rounded-lg border px-4 py-2.5 text-sm font-medium shadow-lg">
				{msg.text}
			</div>
		</div>
	);
}

// --- Entry visuals ------------------------------------------------------------------------------------

const PALETTE = ["#0ea5e9", "#8b5cf6", "#ec4899", "#f97316", "#14b8a6", "#6366f1", "#ef4444", "#84cc16", "#06b6d4", "#a855f7"];

export function Avatar({ name }: { name: string }) {
	let h = 0;
	for (const c of name.toLowerCase()) h = (h * 31 + c.charCodeAt(0)) >>> 0;
	const letter = [...name.trim()][0]?.toUpperCase() ?? "?";
	return (
		<div class="grid size-11 shrink-0 place-items-center rounded-lg text-lg font-semibold text-white" style={{ background: PALETTE[h % PALETTE.length] }}>
			{letter}
		</div>
	);
}

export function Timer({ remainingMs, periodMs }: { remainingMs: number; periodMs: number }) {
	const r = 12;
	const c = 2 * Math.PI * r;
	const secs = Math.ceil(remainingMs / 1000);
	const offset = c * (1 - remainingMs / periodMs);
	return (
		<svg class={`timer size-8${secs <= 5 ? " expiring" : ""}`} viewBox="0 0 30 30" aria-label={`${secs} seconds left`}>
			<circle class="track" cx="15" cy="15" r={r} />
			<circle class="bar" cx="15" cy="15" r={r} stroke-dasharray={c} stroke-dashoffset={offset}
				transform="rotate(-90 15 15)" stroke-linecap="round" />
			<text x="15" y="18.5" text-anchor="middle">{secs}</text>
		</svg>
	);
}

/**
 * Digits-only secret input that opens the numeric keypad on phones.
 * type="password" makes mobile browsers ignore inputMode, so use type="text" masked with
 * -webkit-text-security; where that CSS is unsupported, fall back to type="password".
 */
const CAN_MASK = typeof CSS !== "undefined" && typeof CSS.supports === "function" && CSS.supports("-webkit-text-security", "disc");

export function PinInput({ id, value, onValue, autofocus }: {
	id: string;
	value: string;
	onValue: (digits: string) => void;
	autofocus?: boolean;
}) {
	const onInput = (e: { currentTarget: HTMLInputElement }) => onValue(e.currentTarget.value.replace(/\D/g, ""));
	return CAN_MASK ? (
		<input id={id} type="text" class={inputClass("pin-input")} inputMode="numeric" pattern="[0-9]*" autocomplete="off"
			autocapitalize="off" spellcheck={false} maxLength={64} value={value} autofocus={autofocus} onInput={onInput} />
	) : (
		<input id={id} type="password" class={inputClass()} inputMode="numeric" pattern="[0-9]*" autocomplete="off"
			maxLength={64} value={value} autofocus={autofocus} onInput={onInput} />
	);
}
