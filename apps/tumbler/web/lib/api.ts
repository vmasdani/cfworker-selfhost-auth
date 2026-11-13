// Same-origin JSON API client. The session is an HttpOnly cookie the page cannot read.

import type { KdfParams, Sealed } from "@cfsa/crypto";

export class ApiError extends Error {
	override name = "ApiError";
	constructor(
		readonly status: number,
		readonly code: string,
		message: string,
	) {
		super(message);
	}
}

/** Thrown when the network is unreachable; the app keeps working offline. */
export class OfflineError extends Error {
	override name = "OfflineError";
	constructor() {
		super("You are offline. Changes are kept on this device and sync later.");
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
		throw new OfflineError();
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

export interface RemoteRecord {
	id: string;
	iv: string;
	ct: string;
	revision: number;
	updatedAt: number;
	deleted: boolean;
	seq: number;
}

export interface Invite {
	id: string;
	role: "admin" | "user";
	createdAt: number;
	expiresAt: number;
	usedAt: number | null;
	usedBy: string | null;
}
