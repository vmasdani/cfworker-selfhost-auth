// sdk/coffer.ts must agree with sdk/test-vectors.json (fetch is mocked; no server).
import { afterEach, expect, test } from "bun:test";
import { Coffer } from "../coffer.ts";
import vectors from "../test-vectors.json";

const { input, expected } = vectors;
const realFetch = globalThis.fetch;
afterEach(() => {
	globalThis.fetch = realFetch;
});

test("coffer.ts matches the published test vectors", async () => {
	const seen: { url: string; auth: string | null; method: string; body?: string }[] = [];
	globalThis.fetch = (async (url: string, init: RequestInit) => {
		const auth = new Headers(init.headers).get("Authorization");
		seen.push({ url, auth, method: init.method ?? "GET", body: init.body as string | undefined });
		const path = new URL(url).pathname;
		const json = (v: unknown) => new Response(JSON.stringify(v), { headers: { "Content-Type": "application/json" } });
		if (path === "/api/v1/identity") {
			return json({ clientId: input.clientId, scope: "write", projectId: "p", project: "P", envId: input.envId, environment: "dev", wrappedKey: expected.wrappedKey });
		}
		if (path === "/api/v1/secrets") return json({ secrets: [{ ...expected.secret, version: 1, updatedAt: 0 }] });
		if (path === `/api/v1/secrets/${expected.mac}` && init.method === "PUT") return json({ ...expected.secret, version: 2, updatedAt: 0 });
		if (path === `/api/v1/secrets/${expected.mac}`) return json({ ...expected.secret, version: 1, updatedAt: 0 });
		return new Response(JSON.stringify({ error: "secret_not_found" }), { status: 404 });
	}) as typeof fetch;

	const c = new Coffer("https://coffer.test", input.clientId, input.clientSecret);
	expect(await c.listAllSecrets()).toEqual({ [input.name]: input.value });
	expect(await c.getSecret(input.name)).toBe(input.value);
	expect(seen.every((r) => r.auth === expected.authorizationHeader)).toBe(true);
	expect(seen.some((r) => r.url.endsWith(`/api/v1/secrets/${expected.mac}`))).toBe(true);

	// A write goes to the same mac and is readable with the vector keys.
	expect(await c.writeSecret(input.name, input.value)).toBe(2);
	const put = seen.find((r) => r.method === "PUT")!;
	const body = JSON.parse(put.body!) as { iv: string; ct: string };
	const key = await crypto.subtle.importKey("raw", Buffer.from(expected.encKeyHex, "hex"), "AES-GCM", false, ["decrypt"]);
	const pt = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: Buffer.from(body.iv, "base64"), additionalData: new TextEncoder().encode(`coffer/v1/secret/${input.envId}/${expected.mac}`) },
		key,
		Buffer.from(body.ct, "base64"),
	);
	expect(JSON.parse(new TextDecoder().decode(pt))).toEqual({ name: input.name, value: input.value });
});
