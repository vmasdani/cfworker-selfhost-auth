// Projects, environments, secrets, members and machine identities, decrypted client-side.

import type { Sealed } from "@cfsa/crypto";
import { api } from "./api.ts";
import {
	envCrypto,
	newKey,
	newMachineCredentials,
	unwrapEnvKey,
	unwrapMemberKey,
	wrapEnvKey,
	wrapForMember,
	type EnvCrypto,
	type MachineCredentials,
	type MemberWrapped,
} from "./keys.ts";
import { requireUnlocked } from "./session.ts";

export type Role = "owner" | "member";

export interface Environment {
	id: string;
	name: string;
	secretCount: number;
	crypto: EnvCrypto;
	/** Raw environment key; needed to issue machine identities. */
	key: Uint8Array;
}

export interface Project {
	id: string;
	name: string;
	role: Role;
	createdAt: number;
	key: Uint8Array;
	environments: Environment[];
}

interface RawProject {
	id: string;
	name: string;
	role: Role;
	createdAt: number;
	wrappedKey: MemberWrapped;
	environments: { id: string; name: string; secretCount: number; wrappedKey: Sealed }[];
}

export async function loadProjects(): Promise<Project[]> {
	const u = requireUnlocked();
	const { projects } = await api<{ projects: RawProject[] }>("GET", "/projects");
	return Promise.all(
		projects.map(async (p) => {
			const key = await unwrapMemberKey(u.privateKey, p.wrappedKey, p.id, u.me.id);
			const environments = await Promise.all(
				p.environments.map(async (e) => {
					const envKey = await unwrapEnvKey(key, e.wrappedKey, e.id);
					return { id: e.id, name: e.name, secretCount: e.secretCount, key: envKey, crypto: await envCrypto(e.id, envKey) };
				}),
			);
			return { id: p.id, name: p.name, role: p.role, createdAt: p.createdAt, key, environments };
		}),
	);
}

export async function createProject(name: string, envNames: string[]): Promise<string> {
	const u = requireUnlocked();
	const id = crypto.randomUUID();
	const key = newKey();
	const environments = await Promise.all(
		envNames.map(async (n) => {
			const envId = crypto.randomUUID();
			return { id: envId, name: n, wrappedKey: await wrapEnvKey(key, newKey(), envId) };
		}),
	);
	await api("POST", "/projects", { id, name, wrappedKey: await wrapForMember(key, u.publicKey, id, u.me.id), environments });
	return id;
}

export const renameProject = (p: Project, name: string) => api("PATCH", `/projects/${p.id}`, { name });
export const deleteProject = (p: Project) => api("DELETE", `/projects/${p.id}`);

export async function addEnvironment(p: Project, name: string): Promise<void> {
	const id = crypto.randomUUID();
	await api("POST", `/projects/${p.id}/environments`, { id, name, wrappedKey: await wrapEnvKey(p.key, newKey(), id) });
}

export const renameEnvironment = (e: Environment, name: string) => api("PATCH", `/environments/${e.id}`, { name });
export const deleteEnvironment = (e: Environment) => api("DELETE", `/environments/${e.id}`);

// --- secrets -----------------------------------------------------------------------------------------

export interface Secret {
	mac: string;
	name: string;
	value: string;
	version: number;
	updatedAt: number;
}

type Row = { mac: string; iv: string; ct: string; version: number; updatedAt: number };

export async function listSecrets(e: Environment): Promise<Secret[]> {
	const { secrets } = await api<{ secrets: Row[] }>("GET", `/environments/${e.id}/secrets`);
	const out = await Promise.all(secrets.map(async (r) => ({ ...(await e.crypto.open(r)), mac: r.mac, version: r.version, updatedAt: r.updatedAt })));
	return out.sort((a, b) => a.name.localeCompare(b.name));
}

export async function putSecret(e: Environment, name: string, value: string): Promise<void> {
	const s = await e.crypto.seal(name, value);
	await api("PUT", `/environments/${e.id}/secrets/${s.mac}`, { iv: s.iv, ct: s.ct });
}

export async function deleteSecret(e: Environment, name: string): Promise<void> {
	await api("DELETE", `/environments/${e.id}/secrets/${await e.crypto.mac(name)}`);
}

export interface HistoryItem {
	value: string;
	version: number;
	updatedAt: number;
	updatedBy: string;
	replacedAt: number;
	replacedBy: string;
	deleted: boolean;
}

export async function secretHistory(e: Environment, mac: string): Promise<HistoryItem[]> {
	const { history } = await api<{ history: (Row & { updatedBy: string; replacedAt: number; replacedBy: string; deleted: number })[] }>(
		"GET",
		`/environments/${e.id}/secrets/${mac}/history`,
	);
	return Promise.all(
		history.map(async (h) => ({
			value: (await e.crypto.open({ mac, iv: h.iv, ct: h.ct })).value,
			version: h.version,
			updatedAt: h.updatedAt,
			updatedBy: h.updatedBy,
			replacedAt: h.replacedAt,
			replacedBy: h.replacedBy,
			deleted: h.deleted === 1,
		})),
	);
}

/** Secret names: what a .env file and every SDK accept without quoting. */
export const SECRET_NAME = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;

// --- members -------------------------------------------------------------------------------------------

export interface Member {
	userId: string;
	username: string;
	role: Role;
	addedAt: number;
}

export const listMembers = (p: Project) => api<{ members: Member[] }>("GET", `/projects/${p.id}/members`).then((r) => r.members);

/** Fetch the user's public key, wrap the project key to it, and add them. Returns the key fingerprint. */
export async function addMember(p: Project, username: string, role: Role): Promise<string> {
	const u = await api<{ userId: string; publicKey: string }>("GET", `/users/${encodeURIComponent(username.trim().toLowerCase())}/key`);
	await api("POST", `/projects/${p.id}/members`, { userId: u.userId, role, wrappedKey: await wrapForMember(p.key, u.publicKey, p.id, u.userId) });
	return u.publicKey;
}

export const setMemberRole = (p: Project, userId: string, role: Role) => api("PATCH", `/projects/${p.id}/members/${userId}`, { role });
export const removeMember = (p: Project, userId: string) => api("DELETE", `/projects/${p.id}/members/${userId}`);

// --- machine identities ------------------------------------------------------------------------------

export interface MachineIdentity {
	id: string;
	envId: string;
	name: string;
	scope: "read" | "write";
	createdAt: number;
	lastUsedAt: number | null;
	createdBy: string | null;
}

export const listIdentities = (p: Project) =>
	api<{ identities: MachineIdentity[] }>("GET", `/projects/${p.id}/identities`).then((r) => r.identities);

export async function createIdentity(p: Project, e: Environment, name: string, scope: "read" | "write"): Promise<MachineCredentials> {
	const creds = await newMachineCredentials(e.key);
	await api("POST", `/projects/${p.id}/identities`, { id: creds.clientId, envId: e.id, name, scope, authKey: creds.authKey, wrappedKey: creds.wrappedKey });
	return creds;
}

export const revokeIdentity = (id: string) => api("DELETE", `/identities/${id}`);
