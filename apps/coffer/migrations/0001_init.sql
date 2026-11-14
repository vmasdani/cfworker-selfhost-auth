-- Coffer: initial schema.
-- Zero-knowledge: secret names and values, project keys, environment keys and user private keys are
-- encrypted client-side. The server stores ciphertext, public keys and verifiers only.
-- Project and environment NAMES are plaintext metadata.

-- Accounts (same layout as Tumbler; served by @cfsa/worker-accounts) --------------------------------

CREATE TABLE users (
	id                       TEXT PRIMARY KEY,
	username                 TEXT NOT NULL UNIQUE COLLATE NOCASE,
	role                     TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
	auth_verifier            TEXT NOT NULL,          -- HMAC(SERVER_SECRET, client auth key)
	kdf_salt                 TEXT NOT NULL,
	kdf_params               TEXT NOT NULL,          -- JSON
	wrapped_vault_key        TEXT NOT NULL,          -- vault key wrapped by password-derived key
	recovery_wrapped_key     TEXT NOT NULL,          -- vault key wrapped by recovery key
	recovery_verifier        TEXT NOT NULL,
	login_totp_secret_enc    TEXT,                   -- sealed with SERVER_SECRET
	login_totp_enabled       INTEGER NOT NULL DEFAULT 0,
	login_totp_last_counter  INTEGER NOT NULL DEFAULT 0,
	disabled                 INTEGER NOT NULL DEFAULT 0,
	created_at               INTEGER NOT NULL,
	updated_at               INTEGER NOT NULL
);

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

CREATE TABLE audit_log (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id  TEXT REFERENCES users (id) ON DELETE SET NULL,
	event    TEXT NOT NULL,
	at       INTEGER NOT NULL,
	meta     TEXT                                    -- JSON; never secrets
);
CREATE INDEX audit_log_user_at ON audit_log (user_id, at);

CREATE TABLE rate_limits (
	key           TEXT PRIMARY KEY,
	count         INTEGER NOT NULL,
	window_start  INTEGER NOT NULL
);

-- Coffer ---------------------------------------------------------------------------------------

-- Each user's ECDH P-256 key pair. Others wrap project keys to the public key.
CREATE TABLE user_keys (
	user_id              TEXT PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
	public_key           TEXT NOT NULL,              -- SPKI, base64
	wrapped_private_key  TEXT NOT NULL,              -- PKCS#8 sealed with the user's vault key (JSON)
	created_at           INTEGER NOT NULL
);

CREATE TABLE projects (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	created_by  TEXT REFERENCES users (id) ON DELETE SET NULL,
	created_at  INTEGER NOT NULL
);

-- Members hold the project key, wrapped to their public key (ephemeral ECDH; JSON {epk, iv, ct}).
CREATE TABLE project_members (
	project_id   TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
	user_id      TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	role         TEXT NOT NULL CHECK (role IN ('owner', 'member')),
	wrapped_key  TEXT NOT NULL,
	added_by     TEXT REFERENCES users (id) ON DELETE SET NULL,
	created_at   INTEGER NOT NULL,
	PRIMARY KEY (project_id, user_id)
);
CREATE INDEX project_members_user ON project_members (user_id);

-- Each environment has its own key, wrapped by the project key (JSON {iv, ct}).
CREATE TABLE environments (
	id           TEXT PRIMARY KEY,
	project_id   TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
	name         TEXT NOT NULL,
	position     INTEGER NOT NULL DEFAULT 0,
	wrapped_key  TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	UNIQUE (project_id, name)
);

-- name_mac = hex HMAC-SHA256(index key, name): lets clients address a secret without revealing its name.
-- iv/ct = AES-256-GCM of {"name","value"} under the environment's secret key.
CREATE TABLE secrets (
	env_id      TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
	name_mac    TEXT NOT NULL,
	iv          TEXT NOT NULL,
	ct          TEXT NOT NULL,
	version     INTEGER NOT NULL DEFAULT 1,
	updated_at  INTEGER NOT NULL,
	updated_by  TEXT NOT NULL,                      -- "user:<id>" or "machine:<client id>"
	PRIMARY KEY (env_id, name_mac)
);

-- Previous versions and deletions, newest last. Ciphertext only.
CREATE TABLE secret_history (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	env_id      TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
	name_mac    TEXT NOT NULL,
	iv          TEXT NOT NULL,
	ct          TEXT NOT NULL,
	version     INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	updated_by  TEXT NOT NULL,
	replaced_at INTEGER NOT NULL,
	replaced_by TEXT NOT NULL,
	deleted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX secret_history_env_mac ON secret_history (env_id, name_mac, id);

-- Machine identities: REST API credentials for one environment.
-- id is the client ID. The client secret never reaches the server; only HMAC(SERVER_SECRET, auth key)
-- and the environment key wrapped by the secret's wrap key are stored.
CREATE TABLE machine_identities (
	id             TEXT PRIMARY KEY,
	project_id     TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
	env_id         TEXT NOT NULL REFERENCES environments (id) ON DELETE CASCADE,
	name           TEXT NOT NULL,
	scope          TEXT NOT NULL CHECK (scope IN ('read', 'write')),
	auth_verifier  TEXT NOT NULL,
	wrapped_key    TEXT NOT NULL,
	created_by     TEXT REFERENCES users (id) ON DELETE SET NULL,
	created_at     INTEGER NOT NULL,
	last_used_at   INTEGER,
	revoked_at     INTEGER
);
CREATE INDEX machine_identities_project ON machine_identities (project_id);
