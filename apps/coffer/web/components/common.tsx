import { Card, Button, cn } from "@cfsa/ui";
import { Check, Copy } from "lucide-preact";
import type { ComponentChildren } from "preact";
import { useEffect, useState } from "preact/hooks";
import { copySecret } from "../lib/clipboard.ts";

export const errorMessage = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Seconds after which copied secrets are cleared from the clipboard. */
export const CLIPBOARD_CLEAR_SECONDS = 30;

export function Logo({ class: className }: { class?: string }) {
	return <img src="/icon.svg" alt="" class={cn("size-8", className)} />;
}

export function Brand({ subtitle }: { subtitle?: string }) {
	return (
		<div class="flex flex-col items-center gap-2 text-center">
			<Logo class="size-16" />
			<h1 class="text-xl font-semibold tracking-tight">Coffer</h1>
			{subtitle && <p class="text-muted-foreground text-sm">{subtitle}</p>}
		</div>
	);
}

/** Centered card for sign-in, unlock and other pre-app screens. */
export function AuthScreen({ subtitle, children }: { subtitle?: string; children: ComponentChildren }) {
	return (
		<div class="grid min-h-dvh place-items-center px-4 py-8">
			<Card class="w-full max-w-sm gap-6 px-6 py-7">
				<Brand subtitle={subtitle} />
				{children}
			</Card>
		</div>
	);
}

export function Section({ title, description, actions, children, class: className }: {
	title: ComponentChildren;
	description?: ComponentChildren;
	actions?: ComponentChildren;
	children: ComponentChildren;
	class?: string;
}) {
	return (
		<section class={cn("grid gap-3", className)}>
			<div class="flex flex-wrap items-end justify-between gap-2 px-1">
				<div class="grid gap-1">
					<h2 class="text-sm font-semibold tracking-tight">{title}</h2>
					{description && <p class="text-muted-foreground text-xs leading-relaxed">{description}</p>}
				</div>
				{actions}
			</div>
			<Card class="gap-4 px-5 py-5">{children}</Card>
		</section>
	);
}

export const ErrorText = ({ children }: { children?: ComponentChildren }) =>
	children ? <p class="text-destructive text-sm" role="alert">{children}</p> : null;

export const Hint = ({ children, class: className }: { children?: ComponentChildren; class?: string }) =>
	children ? <p class={cn("text-muted-foreground text-sm leading-relaxed", className)}>{children}</p> : null;

export function EmptyState({ icon, title, children }: { icon?: ComponentChildren; title: string; children?: ComponentChildren }) {
	return (
		<div class="text-muted-foreground grid place-items-center gap-2 rounded-lg border border-dashed px-6 py-10 text-center text-sm">
			{icon && <div class="[&>svg]:size-8">{icon}</div>}
			<p class="text-foreground font-medium">{title}</p>
			{children}
		</div>
	);
}

/** Copy a value; secrets are cleared from the clipboard after a while. */
export function CopyButton({ value, label = "Copy", secret = true, size = "sm", variant = "outline", showLabel = true }: {
	value: string;
	label?: string;
	secret?: boolean;
	size?: "sm" | "icon" | "default";
	variant?: "outline" | "ghost" | "default";
	showLabel?: boolean;
}) {
	const [done, setDone] = useState(false);
	useEffect(() => {
		if (!done) return;
		const t = setTimeout(() => setDone(false), 1500);
		return () => clearTimeout(t);
	}, [done]);
	return (
		<Button variant={variant} size={size} aria-label={label} title={label}
			onClick={async () => {
				await copySecret(value, secret ? CLIPBOARD_CLEAR_SECONDS : 0);
				setDone(true);
				toast(secret ? `Copied. Clipboard clears in ${CLIPBOARD_CLEAR_SECONDS} s.` : "Copied");
			}}>
			{done ? <Check /> : <Copy />}
			{showLabel && size !== "icon" && (done ? "Copied" : label)}
		</Button>
	);
}

export function timeAgo(ms: number | null | undefined): string {
	if (!ms) return "never";
	const s = Math.round((Date.now() - ms) / 1000);
	if (s < 60) return "just now";
	const m = Math.round(s / 60);
	if (m < 60) return `${m} min ago`;
	const h = Math.round(m / 60);
	if (h < 48) return `${h} h ago`;
	return new Date(ms).toLocaleDateString();
}

export function download(filename: string, text: string, type = "text/plain") {
	const url = URL.createObjectURL(new Blob([text], { type }));
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- Toasts -----------------------------------------------------------------------------------------

const toastTarget = new EventTarget();

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
		const t = setTimeout(() => setMsg(null), 2500);
		return () => clearTimeout(t);
	}, [msg]);
	if (!msg) return null;
	return (
		<div class="pointer-events-none fixed inset-x-0 bottom-8 z-50 flex justify-center px-4">
			<div role="status" class="bg-popover text-popover-foreground rounded-lg border px-4 py-2.5 text-sm font-medium shadow-lg">
				{msg.text}
			</div>
		</div>
	);
}
