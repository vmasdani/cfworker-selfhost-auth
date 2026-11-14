// Secret rows. Shared by the dashboard routes (session) and the machine REST API (client credentials).
// The server never sees names or values: rows are addressed by name_mac and hold AES-GCM ciphertext.

import { b64 } from "@cfsa/server-kit";
import { MAX_SECRET_CT } from "./common.ts";

type Obj = Record<string, unknown>;

export interface SecretRow {
	mac: string;
	iv: string;
	ct: string;
	version: number;
	updatedAt: number;
}

const COLUMNS = "name_mac AS mac, iv, ct, version, updated_at AS updatedAt";

export async function listSecrets(db: D1Database, envId: string): Promise<SecretRow[]> {
	const r = await db.prepare(`SELECT ${COLUMNS} FROM secrets WHERE env_id = ? ORDER BY name_mac`).bind(envId).all<SecretRow>();
	return r.results;
}

export function getSecret(db: D1Database, envId: string, mac: string): Promise<SecretRow | null> {
	return db.prepare(`SELECT ${COLUMNS} FROM secrets WHERE env_id = ? AND name_mac = ?`).bind(envId, mac).first<SecretRow>();
}

export function secretBody(o: Obj): { iv: string; ct: string } {
	return { iv: b64(o, "iv", { bytes: 12 }), ct: b64(o, "ct", { max: MAX_SECRET_CT }) };
}

/** Insert or replace; the previous version goes to secret_history. One transaction. */
export async function putSecret(db: D1Database, envId: string, mac: string, s: { iv: string; ct: string }, by: string): Promise<SecretRow> {
	const now = Date.now();
	await db.batch([
		db.prepare(
			`INSERT INTO secret_history (env_id, name_mac, iv, ct, version, updated_at, updated_by, replaced_at, replaced_by, deleted)
			 SELECT env_id, name_mac, iv, ct, version, updated_at, updated_by, ?3, ?4, 0 FROM secrets WHERE env_id = ?1 AND name_mac = ?2`,
		).bind(envId, mac, now, by),
		db.prepare(
			`INSERT INTO secrets (env_id, name_mac, iv, ct, version, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
			 ON CONFLICT (env_id, name_mac) DO UPDATE SET
			   iv = excluded.iv, ct = excluded.ct, version = secrets.version + 1,
			   updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		).bind(envId, mac, s.iv, s.ct, now, by),
	]);
	return (await getSecret(db, envId, mac))!;
}

/** Returns false when there was nothing to delete. */
export async function deleteSecret(db: D1Database, envId: string, mac: string, by: string): Promise<boolean> {
	const now = Date.now();
	const [, del] = await db.batch([
		db.prepare(
			`INSERT INTO secret_history (env_id, name_mac, iv, ct, version, updated_at, updated_by, replaced_at, replaced_by, deleted)
			 SELECT env_id, name_mac, iv, ct, version, updated_at, updated_by, ?3, ?4, 1 FROM secrets WHERE env_id = ?1 AND name_mac = ?2`,
		).bind(envId, mac, now, by),
		db.prepare("DELETE FROM secrets WHERE env_id = ? AND name_mac = ?").bind(envId, mac),
	]);
	return del!.meta.changes === 1;
}

export async function secretHistory(db: D1Database, envId: string, mac: string) {
	const r = await db.prepare(
		`SELECT h.iv, h.ct, h.version, h.updated_at AS updatedAt, h.replaced_at AS replacedAt, h.deleted,
		        COALESCE((SELECT username FROM users WHERE 'user:' || id = h.updated_by), replace(h.updated_by, 'machine:', 'client ')) AS updatedBy,
		        COALESCE((SELECT username FROM users WHERE 'user:' || id = h.replaced_by), replace(h.replaced_by, 'machine:', 'client ')) AS replacedBy
		 FROM secret_history h WHERE h.env_id = ? AND h.name_mac = ? ORDER BY h.id DESC LIMIT 50`,
	).bind(envId, mac).all();
	return r.results;
}
