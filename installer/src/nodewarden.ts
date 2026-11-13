// NodeWarden first-admin claim.
//
// NodeWarden makes the FIRST registered account the admin; later accounts need an invite code.
// A fresh deploy is therefore claimable by anyone who reaches it first. The installer closes that
// window by registering the admin itself immediately after deploy, then proves the account works
// by logging in and decrypting the returned user key.

import { decryptEncString, makeRegistration, normalizeEmail } from "./lib/bitwarden.ts";
import { validateMasterPassword } from "./lib/password.ts";

export class ClaimError extends Error {
	override name = "ClaimError";
}

interface Bootstrap {
	registrationInviteRequired: boolean;
	jwtUnsafeReason: string | null;
	defaultKdfIterations: number;
}

export interface ClaimResult {
	url: string;
	email: string;
}

function originOf(url: string): string {
	const u = new URL(url);
	if (u.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)) {
		throw new ClaimError("Refusing to send credentials over plain HTTP to a non-local host");
	}
	return u.origin;
}

async function json<T>(res: Response): Promise<T> {
	const text = await res.text();
	try {
		return JSON.parse(text) as T;
	} catch {
		throw new ClaimError(`Unexpected response (${res.status}): ${text.slice(0, 200)}`);
	}
}

/** fetch that reports unreachable hosts as a ClaimError instead of a stack trace. */
async function request(url: string, init?: RequestInit): Promise<Response> {
	try {
		return await fetch(url, init);
	} catch (e) {
		throw new ClaimError(`Cannot reach ${new URL(url).origin}: ${e instanceof Error ? e.message : String(e)}`);
	}
}

export async function getBootstrap(origin: string): Promise<Bootstrap> {
	const res = await request(`${origin}/api/web-bootstrap`, { headers: { Accept: "application/json" } });
	if (!res.ok) throw new ClaimError(`GET /api/web-bootstrap failed: ${res.status}`);
	return json<Bootstrap>(res);
}

const ALREADY_CLAIMED =
	"NodeWarden already has an account that this installer did not create. If you did not register it, " +
	"someone else may have claimed the admin account: do not use this instance. Wipe its D1 database " +
	"(and KV namespace in KV mode) and redeploy.";

/**
 * Turn the desired admin username into NodeWarden's login identifier.
 * The Bitwarden protocol logs in by email, so a plain username becomes `<username>@<worker host>`.
 * No mail is ever sent to it. An input that already contains "@" is used as-is.
 */
export function loginFromUsername(username: string, url: string): string {
	const u = normalizeEmail(username);
	if (u.includes("@")) {
		if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(u)) throw new ClaimError(`Invalid email address: ${u}`);
		return u;
	}
	if (!/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(u)) {
		throw new ClaimError("Username may use a-z, 0-9, '.', '_' and '-', and must start and end with a letter or digit");
	}
	const host = new URL(url).hostname;
	// Bitwarden clients validate the login as an email, which needs a dotted domain.
	return `${u}@${host.includes(".") && !/^[\d.]+$/.test(host) ? host : "nodewarden.local"}`;
}

/** Fail early, before asking for credentials, when the instance cannot be claimed. */
export async function assertClaimable(url: string): Promise<void> {
	const boot = await getBootstrap(originOf(url));
	if (boot.jwtUnsafeReason) throw new ClaimError(`NodeWarden JWT_SECRET is ${boot.jwtUnsafeReason}; set it before claiming`);
	if (boot.registrationInviteRequired) throw new ClaimError(ALREADY_CLAIMED);
}

export async function claimFirstAdmin(args: {
	url: string;
	email: string;
	password: string;
	name?: string;
}): Promise<ClaimResult> {
	const origin = originOf(args.url);
	const email = normalizeEmail(args.email);
	if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new ClaimError("Invalid email address");

	const boot = await getBootstrap(origin);
	if (boot.jwtUnsafeReason) throw new ClaimError(`NodeWarden JWT_SECRET is ${boot.jwtUnsafeReason}; set it before claiming`);
	if (boot.registrationInviteRequired) throw new ClaimError(ALREADY_CLAIMED);

	const pwError = validateMasterPassword(args.password, email);
	if (pwError) throw new ClaimError(pwError);
	const reg = await makeRegistration({
		email,
		name: args.name ?? email,
		password: args.password,
		iterations: boot.defaultKdfIterations,
	});

	const res = await request(`${origin}/api/accounts/register`, {
		method: "POST",
		// NodeWarden only accepts same-origin registration writes.
		headers: { "Content-Type": "application/json", Origin: origin },
		body: JSON.stringify(reg.body),
	});
	if (!res.ok) {
		const body = await res.text();
		if (res.status === 403 && /invite/i.test(body)) throw new ClaimError(ALREADY_CLAIMED);
		throw new ClaimError(`Registration failed (${res.status}): ${body.slice(0, 200)}`);
	}

	await verifyLogin(origin, email, reg.masterKeys.masterPasswordHash, reg.masterKeys.stretched, reg.userKey);
	reg.userKey.fill(0);
	return { url: origin, email };
}

/** Log in with the new credentials and check the server returns our encrypted user key intact. */
async function verifyLogin(
	origin: string,
	email: string,
	passwordHash: string,
	stretched: { enc: Uint8Array; mac: Uint8Array },
	userKey: Uint8Array,
): Promise<void> {
	const form = new URLSearchParams({
		grant_type: "password",
		username: email,
		password: passwordHash,
		scope: "api offline_access",
		client_id: "cli",
		deviceType: "8",
		deviceIdentifier: crypto.randomUUID(),
		deviceName: "cfsa-installer",
	});
	const res = await request(`${origin}/identity/connect/token`, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
		body: form,
	});
	const body = await json<{ Key?: string; key?: string; error_description?: string }>(res);
	if (!res.ok) throw new ClaimError(`Account created, but verification login failed: ${body.error_description ?? res.status}`);
	const encKey = body.Key ?? body.key;
	if (!encKey) throw new ClaimError("Account created, but login response has no user key");
	const got = await decryptEncString(encKey, stretched);
	if (got.length !== userKey.length || !got.every((b, i) => b === userKey[i])) {
		throw new ClaimError("Account created, but the server returned a different user key");
	}
}

/** Summary after a successful claim. The master password is never echoed back. */
export function printClaimSummary(r: ClaimResult): void {
	const line = "─".repeat(64);
	console.log(`
${line}
  NodeWarden admin account created

  URL              ${r.url}
  Login (email)    ${r.email}
  Master password  (the one you entered; not shown or stored)

  ⚠  The master password cannot be recovered or reset: losing it
     loses the vault. Do not keep it only inside this NodeWarden vault.
     Keep a copy in a separate password manager (e.g. Proton Pass)
     or written down offline.

  Next: sign in, then enable two-step login (TOTP) under Settings
  and keep the TOTP in Tumbler. Invite other users with invite codes.
${line}
`);
}
