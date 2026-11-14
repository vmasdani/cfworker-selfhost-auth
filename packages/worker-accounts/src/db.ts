import type { KdfParams, Sealed } from "@cfsa/crypto";

export interface UserRow {
	id: string;
	username: string;
	role: "admin" | "user";
	auth_verifier: string;
	kdf_params: string;
	wrapped_vault_key: string;
	recovery_wrapped_key: string;
	recovery_verifier: string;
	login_totp_secret_enc: string | null;
	login_totp_enabled: number;
	login_totp_last_counter: number;
	disabled: number;
	created_at: number;
}

export const USER_COLUMNS =
	"id, username, role, auth_verifier, kdf_params, wrapped_vault_key, recovery_wrapped_key, recovery_verifier, " +
	"login_totp_secret_enc, login_totp_enabled, login_totp_last_counter, disabled, created_at";

export function userByName(db: D1Database, username: string) {
	return db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE username = ?`).bind(username).first<UserRow>();
}

export function userById(db: D1Database, id: string) {
	return db.prepare(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`).bind(id).first<UserRow>();
}

/** What a signed-in client receives: enough to unwrap the vault key locally. */
export interface AccountResponse {
	user: { id: string; username: string; role: "admin" | "user" };
	kdf: KdfParams;
	wrappedVaultKey: Sealed;
	totpEnabled: boolean;
}

export function accountResponse(u: UserRow): AccountResponse {
	return {
		user: { id: u.id, username: u.username, role: u.role },
		kdf: JSON.parse(u.kdf_params) as KdfParams,
		wrappedVaultKey: JSON.parse(u.wrapped_vault_key) as Sealed,
		totpEnabled: u.login_totp_enabled === 1,
	};
}
