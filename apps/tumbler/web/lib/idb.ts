// Minimal IndexedDB wrapper. Stores: `meta` (key/value), `entries` (keyPath id).

import type { EntryRecord } from "./entries.ts";

const DB_NAME = "tumbler";
const DB_VERSION = 1;

let dbPromise: Promise<IDBDatabase> | undefined;

function db(): Promise<IDBDatabase> {
	dbPromise ??= new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onupgradeneeded = () => {
			const d = req.result;
			if (!d.objectStoreNames.contains("meta")) d.createObjectStore("meta");
			if (!d.objectStoreNames.contains("entries")) d.createObjectStore("entries", { keyPath: "id" });
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
	return dbPromise;
}

async function run<T>(
	stores: string[],
	mode: IDBTransactionMode,
	fn: (tx: IDBTransaction) => IDBRequest<T> | void,
): Promise<T | undefined> {
	const tx = (await db()).transaction(stores, mode);
	const req = fn(tx);
	return new Promise((resolve, reject) => {
		tx.oncomplete = () => resolve(req ? req.result : undefined);
		tx.onerror = () => reject(tx.error);
		tx.onabort = () => reject(tx.error);
	});
}

export const meta = {
	get: <T>(key: string) => run<T>(["meta"], "readonly", (tx) => tx.objectStore("meta").get(key) as IDBRequest<T>),
	put: (key: string, value: unknown) => run(["meta"], "readwrite", (tx) => void tx.objectStore("meta").put(value, key)),
	delete: (key: string) => run(["meta"], "readwrite", (tx) => void tx.objectStore("meta").delete(key)),
};

export const records = {
	all: async () =>
		(await run<EntryRecord[]>(["entries"], "readonly", (tx) => tx.objectStore("entries").getAll())) ?? [],
	get: (id: string) =>
		run<EntryRecord>(["entries"], "readonly", (tx) => tx.objectStore("entries").get(id) as IDBRequest<EntryRecord>),
	putMany: (recs: EntryRecord[]) =>
		run(["entries"], "readwrite", (tx) => {
			const s = tx.objectStore("entries");
			for (const r of recs) s.put(r);
		}),
};

/** Ask the browser not to evict our storage under pressure. Best effort. */
export async function requestPersistence(): Promise<boolean> {
	try {
		return (await navigator.storage?.persist?.()) ?? false;
	} catch {
		return false;
	}
}
