// Same-origin JSON API client. The session is an HttpOnly cookie the page cannot read.

import type { KdfParams, Sealed } from "@cfsa/crypto";

export class ApiError extends Error {
	override name = "ApiError";
	readonly status: number;
	readonly code: string;
	constructor(status: number, code: string, message: string) {
		super(message);
		this.status = status;
		this.code = code;
	}
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
	let res: Response;
	try {
		res = await fetch(`/api${path}`, {
			method,
			credentials: "same-origin",
			headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
			body: body !== undefined ? JSON.stringify(body) : undefined,
		});
	} catch {
		throw new Error("Cannot reach the Coffer server. Check your connection.");
	}
	const json = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
	if (!res.ok) throw new ApiError(res.status, json.error ?? "error", json.message ?? `Request failed (${res.status})`);
	return json as T;
}

export interface AccountResponse {
	user: { id: string; username: string; role: "admin" | "user" };
	kdf: KdfParams;
	wrappedVaultKey: Sealed;
	totpEnabled: boolean;
}

export interface Invite {
	id: string;
	role: "admin" | "user";
	createdAt: number;
	expiresAt: number;
	usedAt: number | null;
	usedBy: string | null;
}

export interface UserSummary {
	id: string;
	username: string;
	role: "admin" | "user";
	disabled: number;
	totpEnabled: number;
	createdAt: number;
}
