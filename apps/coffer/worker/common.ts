// Validation and access checks shared by Coffer routes.

import { b64, bad, HttpError, obj, sealed, str } from "@cfsa/server-kit";
import type { Sealed } from "@cfsa/crypto";
import type { Ctx } from "@cfsa/worker-accounts";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const MAC = /^[0-9a-f]{64}$/;
export const CLIENT_ID = /^cfi_[A-Za-z0-9_-]{22}$/;
const ENV_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$/;

/** Max base64 ciphertext of one secret (about 48 KB of plaintext). */
export const MAX_SECRET_CT = 65_536;

type Obj = Record<string, unknown>;

export function uuid(o: Obj, k: string): string {
	const v = str(o, k, { max: 36 });
	if (!UUID.test(v)) throw bad("invalid_request", `${k} must be a lowercase UUID`);
	return v;
}

export function param(c: Ctx, name: string, re: RegExp = UUID): string {
	const v = c.req.param(name) ?? "";
	if (!re.test(v)) throw new HttpError(404, "not_found");
	return v;
}

export function projectName(o: Obj): string {
	const v = str(o, "name", { max: 64 }).trim();
	if (!v) throw bad("invalid_name", "Name is required");
	return v;
}

export function envName(o: Obj, k = "name"): string {
	const v = str(o, k, { max: 32 }).trim();
	if (!ENV_NAME.test(v)) throw bad("invalid_name", "Environment name: 1–32 characters, letters, digits, '.', '_' or '-'");
	return v;
}

/** {iv, ct} sealed with AES-GCM. */
export function sealedKey(o: Obj, k: string): Sealed {
	return sealed(o, k, { max: 256 });
}

/** Project key wrapped to a member's public key: {epk, iv, ct}. */
export function memberWrap(o: Obj, k = "wrappedKey"): Sealed & { epk: string } {
	const w = obj(o[k], k);
	return { epk: b64(w, "epk", { max: 256 }), ...sealed(o, k, { max: 256 }) };
}

export function role(o: Obj, k = "role"): "owner" | "member" {
	const v = o[k] === undefined ? "member" : str(o, k, { max: 8 });
	if (v !== "owner" && v !== "member") throw bad("invalid_role");
	return v;
}

export interface Membership {
	projectId: string;
	role: "owner" | "member";
}

/** The signed-in user's membership; 404 when not a member, so project IDs do not leak. */
export async function membership(c: Ctx, projectId: string, need?: "owner"): Promise<Membership> {
	const row = await c.env.DB.prepare("SELECT role FROM project_members WHERE project_id = ? AND user_id = ?")
		.bind(projectId, c.get("user").id)
		.first<{ role: "owner" | "member" }>();
	if (!row) throw new HttpError(404, "not_found");
	if (need === "owner" && row.role !== "owner") throw new HttpError(403, "owner_only", "Only project owners can do this");
	return { projectId, role: row.role };
}

export async function envMembership(c: Ctx, envId: string): Promise<Membership & { envId: string }> {
	const row = await c.env.DB.prepare(
		`SELECT e.project_id AS projectId, m.role FROM environments e
		 JOIN project_members m ON m.project_id = e.project_id AND m.user_id = ?
		 WHERE e.id = ?`,
	).bind(c.get("user").id, envId).first<Membership>();
	if (!row) throw new HttpError(404, "not_found");
	return { ...row, envId };
}

export const parseJson = <T>(s: string) => JSON.parse(s) as T;
