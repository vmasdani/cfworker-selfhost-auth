// Thin wrapper around the `cf` CLI. Results are JSON on stdout; errors on stderr.
// Never pass secret values as arguments (they would show in process listings): use files.

export interface CfContext {
	profile?: string;
	accountId?: string;
}

export class CfError extends Error {
	override name = "CfError";
	constructor(
		readonly args: string[],
		readonly code: number,
		readonly stderr: string,
	) {
		super(`cf ${args.join(" ")} failed (exit ${code}): ${stderr.trim().split("\n").slice(-4).join(" ").slice(0, 400)}`);
	}
}

export interface RunResult {
	code: number;
	stdout: string;
	stderr: string;
}

export async function cfRun(
	ctx: CfContext,
	args: string[],
	opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<RunResult> {
	const full = [...args, ...(ctx.profile ? ["--profile", ctx.profile] : [])];
	const env = {
		...process.env,
		...(ctx.accountId ? { CLOUDFLARE_ACCOUNT_ID: ctx.accountId } : {}),
		...opts.env,
	};
	const proc = Bun.spawn(["cf", ...full], { cwd: opts.cwd, env, stdin: "ignore", stdout: "pipe", stderr: "pipe" });
	const [stdout, stderr, code] = await Promise.all([
		new Response(proc.stdout).text(),
		new Response(proc.stderr).text(),
		proc.exited,
	]);
	return { code, stdout, stderr };
}

export async function cf<T = unknown>(ctx: CfContext, args: string[], opts?: { cwd?: string; env?: Record<string, string> }): Promise<T> {
	const r = await cfRun(ctx, args, opts);
	if (r.code !== 0) throw new CfError(args, r.code, r.stderr);
	const out = r.stdout.trim();
	if (!out) return undefined as T;
	try {
		return JSON.parse(out) as T;
	} catch {
		return out as T;
	}
}

// --- typed helpers -------------------------------------------------------------------------------

export interface Account {
	id: string;
	name: string;
}

export async function whoami(ctx: CfContext): Promise<{ authenticated: boolean; accounts: Account[] }> {
	const r = await cf<{ authenticated?: boolean; tokenValid?: boolean; accounts?: Account[] }>(ctx, ["auth", "whoami"]);
	return { authenticated: !!(r.authenticated && r.tokenValid), accounts: (r.accounts ?? []).map(({ id, name }) => ({ id, name })) };
}

export interface D1Info {
	uuid: string;
	name: string;
}

export async function findD1(ctx: CfContext, name: string): Promise<D1Info | null> {
	const list = await cf<D1Info[]>(ctx, ["d1", "list", "--name", name]);
	return list.find((d) => d.name === name) ?? null;
}

export async function createD1(ctx: CfContext, name: string): Promise<D1Info> {
	const r = await cf<{ uuid?: string; id?: string }>(ctx, ["d1", "create", "--name", name]);
	const uuid = r?.uuid ?? r?.id;
	if (!uuid) throw new Error("cf d1 create returned no database id");
	return { uuid, name };
}

/** Secret names on a Worker, or null if the Worker does not exist yet. */
export async function workerSecretNames(ctx: CfContext, worker: string): Promise<string[] | null> {
	const r = await cfRun(ctx, ["workers", "secrets", "list", "--worker", worker]);
	if (r.code !== 0) {
		if (/does not exist|10007/i.test(r.stderr)) return null;
		throw new CfError(["workers", "secrets", "list", "--worker", worker], r.code, r.stderr);
	}
	const list = JSON.parse(r.stdout.trim() || "[]") as { name: string }[];
	return list.map((s) => s.name);
}

export interface Zone {
	id: string;
	name: string;
	status: string;
}

/** The zone in the selected account that `hostname` belongs to (longest matching suffix). */
export async function zoneFor(ctx: CfContext, hostname: string): Promise<Zone | null> {
	const labels = hostname.split(".");
	for (let i = 0; i < labels.length - 1; i++) {
		const name = labels.slice(i).join(".");
		const zones = await cf<Zone[]>(ctx, ["zones", "list", "--name", name]);
		const z = zones?.find((x) => x.name === name);
		if (z) return z;
	}
	return null;
}

export interface DnsRecord {
	name: string;
	type: string;
	content?: string;
	/** Set on records Cloudflare manages for a Worker custom domain. */
	meta?: { read_only?: boolean; origin_worker_id?: string };
}

export const isWorkerManaged = (r: DnsRecord) => !!(r.meta?.read_only && r.meta.origin_worker_id);

export async function dnsRecordsNamed(ctx: CfContext, zone: string, hostname: string): Promise<DnsRecord[]> {
	const all = await cf<DnsRecord[]>(ctx, ["dns", "records", "list", "--zone", zone, "--name", hostname]);
	return (all ?? []).filter((r) => r.name === hostname);
}

export interface KvNamespace {
	id: string;
	title: string;
}

export async function findKv(ctx: CfContext, title: string): Promise<KvNamespace | null> {
	const list = await cf<KvNamespace[]>(ctx, ["kv", "namespaces", "list"]);
	return (list ?? []).find((n) => n.title === title) ?? null;
}

export async function createKv(ctx: CfContext, title: string): Promise<KvNamespace> {
	const r = await cf<{ id?: string; title?: string }>(ctx, ["kv", "namespaces", "create", "--title", title]);
	if (!r?.id) throw new Error("cf kv namespaces create returned no id");
	return { id: r.id, title };
}
