// Opaque session tokens in an HttpOnly cookie. The database stores only SHA-256(token).

import { randomBytes, sha256, toB64, toB64Url, utf8 } from "@cfsa/crypto";

export const SESSION_COOKIE = "__Host-tumbler_session";
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** Extend a session's expiry at most once per this interval, to limit writes. */
const SLIDE_EVERY_MS = 24 * 60 * 60 * 1000;

export interface SessionRow {
	id: string;
	user_id: string;
	expires_at: number;
	last_seen_at: number;
}

const hashToken = async (token: string) => toB64(await sha256(utf8.encode(token)));

export async function createSession(db: D1Database, userId: string, now = Date.now()): Promise<{ id: string; token: string }> {
	const token = toB64Url(randomBytes(32));
	const id = crypto.randomUUID();
	await db
		.prepare("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)")
		.bind(id, userId, await hashToken(token), now, now + SESSION_TTL_MS, now)
		.run();
	return { id, token };
}

export async function findSession(db: D1Database, token: string, now = Date.now()): Promise<SessionRow | null> {
	if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
	const row = await db
		.prepare("SELECT id, user_id, expires_at, last_seen_at FROM sessions WHERE token_hash = ?")
		.bind(await hashToken(token))
		.first<SessionRow>();
	if (!row) return null;
	if (row.expires_at <= now) {
		await db.prepare("DELETE FROM sessions WHERE id = ?").bind(row.id).run();
		return null;
	}
	if (now - row.last_seen_at > SLIDE_EVERY_MS) {
		await db
			.prepare("UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?")
			.bind(now, now + SESSION_TTL_MS, row.id)
			.run();
	}
	return row;
}

export async function deleteSession(db: D1Database, id: string): Promise<void> {
	await db.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
}

/** Sign out everywhere else, e.g. after a password change. */
export async function deleteOtherSessions(db: D1Database, userId: string, keepId: string | null): Promise<void> {
	await db.prepare("DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?").bind(userId, keepId).run();
}

export function sessionCookie(token: string): string {
	return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}`;
}

export function clearSessionCookie(): string {
	return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export function readSessionCookie(header: string | null | undefined): string | null {
	if (!header) return null;
	for (const part of header.split(";")) {
		const [k, ...v] = part.trim().split("=");
		if (k === SESSION_COOKIE) return v.join("=");
	}
	return null;
}
