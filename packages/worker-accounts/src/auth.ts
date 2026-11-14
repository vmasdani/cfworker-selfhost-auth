// Accounts: pre-login, login (+ TOTP), first-admin setup, invite registration, recovery, password, login TOTP.

import { base32Encode, base32Decode, formatOtpauthUri, hotp, importOtpKey, totpCounter } from "@cfsa/totp";
import { DEFAULT_PBKDF2_ITERATIONS, randomBytes, sha256, toB64, utf8, type AccountMaterial } from "@cfsa/crypto";
import {
	accountMaterial,
	assertNotLimited,
	b64,
	bad,
	clear,
	clearSessionCookie,
	createSession,
	deleteOtherSessions,
	deleteSession,
	findSession,
	hit,
	HttpError,
	optStr,
	passwordMaterial,
	readSessionCookie,
	sessionCookie,
	str,
	timingSafeEqualStrings,
	username as usernameField,
	type Limit,
} from "@cfsa/server-kit";
import type { Hono } from "hono";
import { audit, body, clientIp, requireSession, type AppEnv, type Ctx } from "./app.ts";
import { accountResponse, userById, userByName, type UserRow } from "./db.ts";

const MIN = 60_000;
const loginLimits = (c: Ctx, u: string): Limit[] => [
	{ key: `login:u:${u}`, max: 10, windowMs: 15 * MIN },
	{ key: `login:ip:${clientIp(c)}`, max: 30, windowMs: 15 * MIN },
];
const ipLimit = (c: Ctx, scope: string, max = 20): Limit[] => [{ key: `${scope}:ip:${clientIp(c)}`, max, windowMs: 15 * MIN }];

async function signIn(c: Ctx, user: UserRow) {
	const { token } = await createSession(c.env.DB, user.id);
	c.header("Set-Cookie", sessionCookie(token, c.get("cfg").cookie));
	return c.json(accountResponse(user));
}

const totpAad = (c: Ctx, userId: string) => `${c.get("cfg").aadPrefix}/login-totp/v1/${userId}`;

/** Accepts the current, previous or next 30 s step, and never the same step twice. */
async function checkLoginTotp(c: Ctx, user: UserRow, code: string): Promise<boolean> {
	if (!user.login_totp_secret_enc || !/^\d{6}$/.test(code)) return false;
	const secret = await c.get("keys").openSecret(JSON.parse(user.login_totp_secret_enc), totpAad(c, user.id));
	const key = await importOtpKey(base32Decode(secret));
	const now = totpCounter(Date.now());
	for (const step of [now, now - 1, now + 1]) {
		if (step <= user.login_totp_last_counter) continue;
		if ((await hotp(key, step)) === code) {
			const r = await c.env.DB.prepare(
				"UPDATE users SET login_totp_last_counter = ? WHERE id = ? AND login_totp_last_counter < ?",
			).bind(step, user.id, step).run();
			return r.meta.changes === 1;
		}
	}
	return false;
}

function insertUserValues(id: string, uname: string, m: AccountMaterial, verifiers: { auth: string; recovery: string }) {
	const now = Date.now();
	return [
		id,
		uname,
		verifiers.auth,
		m.kdf.salt,
		JSON.stringify(m.kdf),
		JSON.stringify(m.wrappedVaultKey),
		JSON.stringify(m.recoveryWrappedKey),
		verifiers.recovery,
		now,
		now,
	] as const;
}

const INSERT_COLUMNS =
	"id, username, role, auth_verifier, kdf_salt, kdf_params, wrapped_vault_key, recovery_wrapped_key, recovery_verifier, created_at, updated_at";

async function verifiers(c: Ctx, m: AccountMaterial) {
	const keys = c.get("keys");
	return { auth: await keys.verifier(m.authKey), recovery: await keys.verifier(m.recoveryAuthKey) };
}

export function authRoutes(app: Hono<AppEnv>) {
	app.post("/prelogin", async (c) => {
		const u = usernameField(await body(c));
		const user = await userByName(c.env.DB, u);
		if (user) return c.json({ kdf: JSON.parse(user.kdf_params) });
		return c.json({ kdf: { alg: "pbkdf2-sha256", iterations: DEFAULT_PBKDF2_ITERATIONS, salt: await c.get("keys").decoySalt(u) } });
	});

	app.post("/login", async (c) => {
		const b = await body(c);
		const u = usernameField(b);
		const authKey = b64(b, "authKey", { bytes: 32 });
		const totp = optStr(b, "totp", { max: 16 });
		const limits = loginLimits(c, u);
		await assertNotLimited(c.env.DB, limits);
		const user = await userByName(c.env.DB, u);
		if (!user || !(await c.get("keys").verify(authKey, user.auth_verifier))) {
			await hit(c.env.DB, limits);
			throw new HttpError(401, "invalid_credentials", "Wrong username or password");
		}
		if (user.disabled) throw new HttpError(403, "account_disabled", "This account is disabled");
		if (user.login_totp_enabled) {
			if (!totp) throw new HttpError(401, "totp_required", "Enter the code from your authenticator");
			if (!(await checkLoginTotp(c, user, totp.trim()))) {
				await hit(c.env.DB, limits);
				throw new HttpError(401, "invalid_totp", "Wrong or reused code");
			}
		}
		await clear(c.env.DB, [limits[0]!.key]);
		await audit(c, user.id, "login");
		return signIn(c, user);
	});

	app.post("/logout", async (c) => {
		const token = readSessionCookie(c.req.header("Cookie"), c.get("cfg").cookie);
		const session = token ? await findSession(c.env.DB, token) : null;
		if (session) await deleteSession(c.env.DB, session.id);
		c.header("Set-Cookie", clearSessionCookie(c.get("cfg").cookie));
		return c.json({ ok: true });
	});

	app.get("/session", requireSession, (c) => c.json(accountResponse(c.get("user"))));

	// First admin. Works only while there are no users, and only with ADMIN_SETUP_TOKEN.
	app.get("/setup", async (c) => {
		const row = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
		return c.json({ needed: (row?.n ?? 0) === 0, tokenConfigured: !!c.env.ADMIN_SETUP_TOKEN });
	});

	app.post("/setup", async (c) => {
		const limits = ipLimit(c, "setup", 10);
		await assertNotLimited(c.env.DB, limits);
		const b = await body(c);
		const token = str(b, "setupToken", { max: 256 });
		const expected = c.env.ADMIN_SETUP_TOKEN;
		if (!expected || expected.length < 32 || !(await timingSafeEqualStrings(token, expected))) {
			await hit(c.env.DB, limits);
			throw new HttpError(403, "invalid_setup_token");
		}
		const u = usernameField(b);
		const m = accountMaterial(b);
		const id = crypto.randomUUID();
		const v = await verifiers(c, m);
		const r = await c.env.DB.prepare(
			`INSERT INTO users (${INSERT_COLUMNS}) SELECT ?1, ?2, 'admin', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
			 WHERE NOT EXISTS (SELECT 1 FROM users)`,
		).bind(...insertUserValues(id, u, m, v)).run();
		if (r.meta.changes !== 1) throw new HttpError(409, "already_set_up", "This server already has accounts");
		await audit(c, id, "setup_admin");
		return signIn(c, (await userById(c.env.DB, id))!);
	});

	app.get("/invites/check", async (c) => {
		const limits = ipLimit(c, "invite");
		await assertNotLimited(c.env.DB, limits);
		await hit(c.env.DB, limits);
		const token = c.req.query("token") ?? "";
		const row = await c.env.DB.prepare("SELECT expires_at FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?")
			.bind(await inviteHash(token), Date.now())
			.first<{ expires_at: number }>();
		return c.json({ valid: !!row, expiresAt: row?.expires_at ?? null });
	});

	app.post("/register", async (c) => {
		const limits = ipLimit(c, "register");
		await assertNotLimited(c.env.DB, limits);
		await hit(c.env.DB, limits);
		const b = await body(c);
		const tokenHash = await inviteHash(str(b, "invite", { max: 128 }));
		const u = usernameField(b);
		const m = accountMaterial(b);
		const id = crypto.randomUUID();
		const v = await verifiers(c, m);
		const now = Date.now();
		if (await userByName(c.env.DB, u)) throw new HttpError(409, "username_taken", "That username is taken");
		// One transaction: create the user only if the invite is unused and unexpired, then consume it.
		const [ins] = await c.env.DB.batch([
			c.env.DB.prepare(
				`INSERT INTO users (${INSERT_COLUMNS})
				 SELECT ?1, ?2, i.role, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10 FROM invites i
				 WHERE i.token_hash = ?11 AND i.used_at IS NULL AND i.expires_at > ?9`,
			).bind(...insertUserValues(id, u, m, v), tokenHash),
			c.env.DB.prepare(
				"UPDATE invites SET used_at = ?1, used_by = ?2 WHERE token_hash = ?3 AND used_at IS NULL AND EXISTS (SELECT 1 FROM users WHERE id = ?2)",
			).bind(now, id, tokenHash),
		]);
		if (ins!.meta.changes !== 1) throw new HttpError(403, "invalid_invite", "This invite link is invalid, used or expired");
		await audit(c, id, "register");
		return signIn(c, (await userById(c.env.DB, id))!);
	});

	// Recovery: prove possession of the recovery key, get the recovery-wrapped vault key, then set a new password.
	const recoveryUser = async (c: Ctx, b: Record<string, unknown>) => {
		const u = usernameField(b);
		const proof = b64(b, "recoveryAuthKey", { bytes: 32 });
		const limits = loginLimits(c, u).map((l) => ({ ...l, key: l.key.replace("login:", "recover:") }));
		await assertNotLimited(c.env.DB, limits);
		const user = await userByName(c.env.DB, u);
		if (!user || !(await c.get("keys").verify(proof, user.recovery_verifier))) {
			await hit(c.env.DB, limits);
			throw new HttpError(401, "invalid_recovery_key", "Wrong username or recovery key");
		}
		if (user.disabled) throw new HttpError(403, "account_disabled");
		return user;
	};

	app.post("/recover/start", async (c) => {
		const user = await recoveryUser(c, await body(c));
		return c.json({ recoveryWrappedKey: JSON.parse(user.recovery_wrapped_key) });
	});

	app.post("/recover/finish", async (c) => {
		const b = await body(c);
		const user = await recoveryUser(c, b);
		const m = passwordMaterial(b);
		await c.env.DB.batch([
			c.env.DB.prepare(
				`UPDATE users SET auth_verifier = ?, kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?,
				 login_totp_enabled = 0, login_totp_secret_enc = NULL, updated_at = ? WHERE id = ?`,
			).bind(await c.get("keys").verifier(m.authKey), m.kdf.salt, JSON.stringify(m.kdf), JSON.stringify(m.wrappedVaultKey), Date.now(), user.id),
			c.env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(user.id),
		]);
		await audit(c, user.id, "recover");
		return signIn(c, (await userById(c.env.DB, user.id))!);
	});

	app.post("/account/password", requireSession, async (c) => {
		const b = await body(c);
		const user = c.get("user");
		if (!(await c.get("keys").verify(b64(b, "currentAuthKey", { bytes: 32 }), user.auth_verifier))) {
			throw new HttpError(401, "invalid_credentials", "Current password is wrong");
		}
		const m = passwordMaterial(b);
		await c.env.DB.prepare(
			"UPDATE users SET auth_verifier = ?, kdf_salt = ?, kdf_params = ?, wrapped_vault_key = ?, updated_at = ? WHERE id = ?",
		).bind(await c.get("keys").verifier(m.authKey), m.kdf.salt, JSON.stringify(m.kdf), JSON.stringify(m.wrappedVaultKey), Date.now(), user.id).run();
		await deleteOtherSessions(c.env.DB, user.id, c.get("session").id);
		await audit(c, user.id, "password_change");
		return c.json(accountResponse((await userById(c.env.DB, user.id))!));
	});

	// Login TOTP: setup stores a pending secret; enable confirms one code; disable needs the password.
	app.post("/account/totp/setup", requireSession, async (c) => {
		const user = c.get("user");
		if (user.login_totp_enabled) throw bad("totp_already_enabled");
		const secret = base32Encode(randomBytes(20), { padding: false });
		const sealed = await c.get("keys").sealSecret(secret, totpAad(c, user.id));
		await c.env.DB.prepare("UPDATE users SET login_totp_secret_enc = ?, login_totp_last_counter = 0 WHERE id = ?")
			.bind(JSON.stringify(sealed), user.id).run();
		const issuer = `${c.get("cfg").appName} (${new URL(c.req.url).host})`;
		const uri = formatOtpauthUri({ type: "totp", issuer, account: user.username, secret, algorithm: "SHA1", digits: 6, period: 30, counter: 0 });
		return c.json({ secret, uri });
	});

	app.post("/account/totp/enable", requireSession, async (c) => {
		const code = str(await body(c), "code", { max: 16 }).trim();
		const user = (await userById(c.env.DB, c.get("user").id))!;
		if (user.login_totp_enabled) throw bad("totp_already_enabled");
		if (!(await checkLoginTotp(c, user, code))) throw new HttpError(400, "invalid_totp", "Wrong code. Check the time on your device.");
		await c.env.DB.prepare("UPDATE users SET login_totp_enabled = 1 WHERE id = ?").bind(user.id).run();
		await audit(c, user.id, "totp_enable");
		return c.json({ ok: true });
	});

	app.post("/account/totp/disable", requireSession, async (c) => {
		const user = c.get("user");
		if (!(await c.get("keys").verify(b64(await body(c), "authKey", { bytes: 32 }), user.auth_verifier))) {
			throw new HttpError(401, "invalid_credentials", "Password is wrong");
		}
		await c.env.DB.prepare("UPDATE users SET login_totp_enabled = 0, login_totp_secret_enc = NULL WHERE id = ?").bind(user.id).run();
		await audit(c, user.id, "totp_disable");
		return c.json({ ok: true });
	});
}

export async function inviteHash(token: string): Promise<string> {
	return toB64(await sha256(utf8.encode(token)));
}

