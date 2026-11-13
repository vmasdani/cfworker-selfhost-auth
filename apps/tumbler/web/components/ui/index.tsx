// shadcn/ui components ported to Preact: same Tailwind class recipes, no React or Radix.

import { clsx, type ClassValue } from "clsx";
import type { ComponentChildren, ComponentProps } from "preact";
import { twMerge } from "tailwind-merge";
import { ChevronDown } from "lucide-preact";

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

// --- Button ----------------------------------------------------------------------------------------

const buttonBase =
	"inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] cursor-pointer";

const buttonVariants = {
	default: "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90",
	destructive: "bg-destructive text-white shadow-xs hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:bg-destructive/60",
	outline: "border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50",
	secondary: "bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80",
	ghost: "hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50",
	link: "text-primary underline-offset-4 hover:underline h-auto px-0",
	"destructive-outline": "border border-destructive/40 bg-background text-destructive shadow-xs hover:bg-destructive/10 dark:bg-input/30",
} as const;

const buttonSizes = {
	default: "h-10 px-4 py-2 has-[>svg]:px-3",
	sm: "h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5",
	lg: "h-11 rounded-md px-6 has-[>svg]:px-4",
	icon: "size-10",
} as const;

export type ButtonProps = ComponentProps<"button"> & {
	variant?: keyof typeof buttonVariants;
	size?: keyof typeof buttonSizes;
};

export function buttonClass(variant: ButtonProps["variant"] = "default", size: ButtonProps["size"] = "default", extra?: ClassValue) {
	return cn(buttonBase, buttonVariants[variant], buttonSizes[size], extra);
}

export function Button({ variant, size, class: className, type = "button", ...props }: ButtonProps) {
	return <button type={type} class={buttonClass(variant, size, className as ClassValue)} {...props} />;
}

// --- Form controls ---------------------------------------------------------------------------------

const fieldBase =
	"placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground dark:bg-input/30 border-input w-full min-w-0 rounded-md border bg-transparent px-3 text-base shadow-xs transition-[color,box-shadow] outline-none disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 aria-invalid:border-destructive read-only:bg-muted/50";

export const inputClass = (extra?: ClassValue) => cn(fieldBase, "flex h-10 py-1", extra);

export function Input({ class: className, ...props }: ComponentProps<"input">) {
	// Preact types <input> as a union per `type`; the props are passed through unchanged.
	return <input class={inputClass(className as ClassValue)} {...(props as Record<string, unknown>)} />;
}

export function Textarea({ class: className, ...props }: ComponentProps<"textarea">) {
	return <textarea class={cn(fieldBase, "flex min-h-24 py-2 font-mono text-sm md:text-sm", className as ClassValue)} {...props} />;
}

export function Select({ class: className, ...props }: ComponentProps<"select">) {
	return (
		<div class="relative">
			<select class={cn(fieldBase, "h-10 appearance-none pr-9", className as ClassValue)} {...props} />
			<ChevronDown class="text-muted-foreground pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2" />
		</div>
	);
}

export function Label({ class: className, ...props }: ComponentProps<"label">) {
	return <label class={cn("flex items-center gap-2 text-sm leading-none font-medium select-none", className as ClassValue)} {...props} />;
}

/** Label + control + optional hint, stacked. */
export function Field({ label, htmlFor, hint, children, class: className }: {
	label?: ComponentChildren;
	htmlFor?: string;
	hint?: ComponentChildren;
	children: ComponentChildren;
	class?: string;
}) {
	return (
		<div class={cn("grid gap-2", className)}>
			{label && <Label for={htmlFor}>{label}</Label>}
			{children}
			{hint && <p class="text-muted-foreground text-xs leading-relaxed">{hint}</p>}
		</div>
	);
}

export function Checkbox({ class: className, children, ...props }: ComponentProps<"input"> & { children?: ComponentChildren }) {
	return (
		<label class={cn("flex items-start gap-3 text-sm leading-snug cursor-pointer", className as ClassValue)}>
			<input type="checkbox" class="mt-0.5 size-4 shrink-0 rounded-[4px] border-input accent-primary cursor-pointer" {...(props as Record<string, unknown>)} />
			<span>{children}</span>
		</label>
	);
}

export function Switch({ checked, onChange, label, id }: { checked: boolean; onChange: (v: boolean) => void; label: string; id?: string }) {
	const state = checked ? "checked" : "unchecked";
	return (
		<button
			id={id}
			type="button"
			role="switch"
			aria-checked={checked}
			aria-label={label}
			data-state={state}
			onClick={() => onChange(!checked)}
			class="peer data-[state=checked]:bg-primary data-[state=unchecked]:bg-input dark:data-[state=unchecked]:bg-input/80 inline-flex h-6 w-11 shrink-0 items-center rounded-full border border-transparent shadow-xs transition-all outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 cursor-pointer"
		>
			<span
				data-state={state}
				class="bg-background dark:data-[state=unchecked]:bg-foreground dark:data-[state=checked]:bg-primary-foreground pointer-events-none block size-5 rounded-full ring-0 transition-transform data-[state=checked]:translate-x-[calc(100%-0px)] data-[state=unchecked]:translate-x-0.5"
			/>
		</button>
	);
}

// --- Layout ------------------------------------------------------------------------------------------

export function Card({ class: className, ...props }: ComponentProps<"div">) {
	return <div class={cn("bg-card text-card-foreground flex flex-col gap-5 rounded-xl border py-5 shadow-sm", className as ClassValue)} {...props} />;
}

export function CardHeader({ class: className, ...props }: ComponentProps<"div">) {
	return <div class={cn("grid gap-1.5 px-5", className as ClassValue)} {...props} />;
}

export function CardTitle({ class: className, ...props }: ComponentProps<"div">) {
	return <div class={cn("leading-none font-semibold", className as ClassValue)} {...props} />;
}

export function CardDescription({ class: className, ...props }: ComponentProps<"div">) {
	return <div class={cn("text-muted-foreground text-sm", className as ClassValue)} {...props} />;
}

export function CardContent({ class: className, ...props }: ComponentProps<"div">) {
	return <div class={cn("grid gap-4 px-5", className as ClassValue)} {...props} />;
}

export function Separator({ class: className }: { class?: string }) {
	return <div role="separator" class={cn("bg-border h-px w-full shrink-0", className)} />;
}

// --- Feedback ------------------------------------------------------------------------------------

const badgeVariants = {
	default: "border-transparent bg-primary text-primary-foreground",
	secondary: "border-transparent bg-secondary text-secondary-foreground",
	destructive: "border-transparent bg-destructive text-white",
	outline: "text-foreground",
	warning: "border-transparent bg-warning/15 text-warning",
} as const;

export function Badge({ variant = "secondary", class: className, ...props }: ComponentProps<"span"> & { variant?: keyof typeof badgeVariants }) {
	return (
		<span
			class={cn("inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-xs font-medium w-fit whitespace-nowrap shrink-0 gap-1 [&>svg]:size-3", badgeVariants[variant], className as ClassValue)}
			{...props}
		/>
	);
}

const alertVariants = {
	default: "bg-card text-card-foreground",
	destructive: "text-destructive bg-card [&>svg]:text-current",
	warning: "border-warning/40 bg-warning/10 [&>svg]:text-warning",
	success: "border-primary/30 bg-primary/10 [&>svg]:text-primary",
} as const;

export function Alert({ variant = "default", icon, title, children, class: className }: {
	variant?: keyof typeof alertVariants;
	icon?: ComponentChildren;
	title?: ComponentChildren;
	children?: ComponentChildren;
	class?: string;
}) {
	return (
		<div
			role={variant === "destructive" || variant === "warning" ? "alert" : "status"}
			class={cn(
				"relative w-full rounded-lg border px-4 py-3 text-sm grid has-[>svg]:grid-cols-[calc(var(--spacing)*4)_1fr] grid-cols-[0_1fr] has-[>svg]:gap-x-3 gap-y-1 items-start [&>svg]:size-4 [&>svg]:translate-y-0.5",
				alertVariants[variant],
				className,
			)}
		>
			{icon}
			{title && <div class="col-start-2 font-medium tracking-tight">{title}</div>}
			{children && <div class="col-start-2 grid gap-1.5 text-sm leading-relaxed [&_ul]:list-disc [&_ul]:pl-4 [&_ul]:grid [&_ul]:gap-1">{children}</div>}
		</div>
	);
}

// --- Tabs (segmented control) ----------------------------------------------------------------------

export function Tabs<T extends string>({ value, onChange, items }: {
	value: T;
	onChange: (v: T) => void;
	items: { value: T; label: ComponentChildren }[];
}) {
	return (
		<div role="tablist" class="bg-muted text-muted-foreground inline-flex h-10 w-full items-center justify-center rounded-lg p-[3px]">
			{items.map((it) => {
				const active = it.value === value;
				return (
					<button
						type="button"
						role="tab"
						aria-selected={active}
						data-state={active ? "active" : "inactive"}
						onClick={() => onChange(it.value)}
						class="data-[state=active]:bg-background dark:data-[state=active]:text-foreground focus-visible:ring-ring/50 dark:data-[state=active]:border-input dark:data-[state=active]:bg-input/30 text-foreground dark:text-muted-foreground inline-flex h-full flex-1 items-center justify-center gap-1.5 rounded-md border border-transparent px-2 py-1 text-sm font-medium whitespace-nowrap transition-[color,box-shadow] focus-visible:ring-[3px] focus-visible:outline-1 data-[state=active]:shadow-sm [&_svg]:size-4 cursor-pointer"
					>
						{it.label}
					</button>
				);
			})}
		</div>
	);
}
