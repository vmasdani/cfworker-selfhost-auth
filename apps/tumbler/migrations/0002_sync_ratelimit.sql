-- Sync cursor, rate limiting, login TOTP replay protection.

-- Per-user monotonically increasing change number; clients pull "seq > cursor".
ALTER TABLE entries ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;
CREATE INDEX entries_user_seq ON entries (user_id, seq);

-- Last accepted login TOTP time step, so a code cannot be replayed.
ALTER TABLE users ADD COLUMN login_totp_last_counter INTEGER NOT NULL DEFAULT 0;

-- Fixed-window failure counters, keyed e.g. "login:u:<username>" or "login:ip:<ip>".
CREATE TABLE rate_limits (
	key           TEXT PRIMARY KEY,
	count         INTEGER NOT NULL,
	window_start  INTEGER NOT NULL
);
