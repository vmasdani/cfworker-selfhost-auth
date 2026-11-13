-- Tumbler Authenticator: initial schema (draft).
-- Zero-knowledge: the server never sees TOTP secrets or the vault key.
-- Everything in `entries` is client-side encrypted ciphertext.

CREATE TABLE users (
	id                     TEXT PRIMARY KEY,
	username               TEXT NOT NULL UNIQUE COLLATE NOCASE,
	role                   TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
	-- HMAC(SERVER_SECRET, client auth key). The auth key is derived client-side
	-- and is separate from the encryption key.
	auth_verifier          TEXT NOT NULL,
	kdf_salt               TEXT NOT NULL,
	kdf_params             TEXT NOT NULL,           -- JSON: algorithm, iterations/memory
	wrapped_vault_key      TEXT NOT NULL,           -- vault key wrapped by password-derived key
	recovery_wrapped_key   TEXT NOT NULL,           -- vault key wrapped by recovery key
	recovery_verifier      TEXT NOT NULL,           -- HMAC(SERVER_SECRET, recovery auth key)
	-- Account-login 2FA (TOTP). Secret encrypted at rest with SERVER_SECRET.
	login_totp_secret_enc  TEXT,
	login_totp_enabled     INTEGER NOT NULL DEFAULT 0,
	disabled               INTEGER NOT NULL DEFAULT 0,
	created_at             INTEGER NOT NULL,
	updated_at             INTEGER NOT NULL
);

-- Single-use invite links. Only the token hash is stored.
CREATE TABLE invites (
	id          TEXT PRIMARY KEY,
	token_hash  TEXT NOT NULL UNIQUE,
	role        TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
	created_by  TEXT NOT NULL REFERENCES users (id),
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL,
	used_at     INTEGER,
	used_by     TEXT REFERENCES users (id)
);

CREATE TABLE sessions (
	id            TEXT PRIMARY KEY,
	user_id       TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	token_hash    TEXT NOT NULL UNIQUE,
	created_at    INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL,
	last_seen_at  INTEGER NOT NULL
);
CREATE INDEX sessions_user_id ON sessions (user_id);

-- One encrypted row per authenticator entry. Last-write-wins per entry; deletes are tombstones.
CREATE TABLE entries (
	user_id     TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	id          TEXT NOT NULL,                      -- client-generated UUID
	ciphertext  TEXT NOT NULL,
	iv          TEXT NOT NULL,
	revision    INTEGER NOT NULL DEFAULT 1,
	updated_at  INTEGER NOT NULL,
	deleted     INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (user_id, id)
);
CREATE INDEX entries_user_updated ON entries (user_id, updated_at);

CREATE TABLE audit_log (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id  TEXT REFERENCES users (id) ON DELETE SET NULL,
	event    TEXT NOT NULL,
	at       INTEGER NOT NULL,
	meta     TEXT                                   -- JSON; never secrets
);
CREATE INDEX audit_log_user_at ON audit_log (user_id, at);
