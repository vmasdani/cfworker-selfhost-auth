// Bitwarden client-side key derivation for account registration (KDF type 0: PBKDF2-SHA256).
// Matches the official clients and NodeWarden's web vault (webapp/src/lib/api/auth.ts).
//
//   masterKey          = PBKDF2-SHA256(password, salt = email, iterations, 32)
//   masterPasswordHash = PBKDF2-SHA256(masterKey, salt = password, 1, 32)       -> sent to server
//   stretched enc/mac  = HKDF-Expand-SHA256(masterKey, "enc" | "mac", 32)
//   userKey            = random 64 bytes (32 enc + 32 mac)
//   key                = EncString type 2 of userKey under stretched enc/mac    -> sent to server
//   RSA-2048 OAEP/SHA-1 key pair; private key (PKCS#8) encrypted under userKey -> sent to server

const subtle = crypto.subtle;
const te = new TextEncoder();

export const DEFAULT_KDF_ITERATIONS = 600_000;

const bytes = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
export const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
export const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));

/** Bitwarden normalizes the email before using it as the KDF salt. */
export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}

export async function pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
	const key = await subtle.importKey("raw", bytes(password), "PBKDF2", false, ["deriveBits"]);
	return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bytes(salt), iterations }, key, 256));
}

async function hmac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
	const k = await subtle.importKey("raw", bytes(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	return new Uint8Array(await subtle.sign("HMAC", k, bytes(data)));
}

/** HKDF-Expand (RFC 5869 §2.3) with SHA-256. */
export async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
	const out = new Uint8Array(length);
	let prev: Uint8Array = new Uint8Array(0);
	for (let offset = 0, i = 1; offset < length; i++) {
		const input = new Uint8Array(prev.length + info.length + 1);
		input.set(prev, 0);
		input.set(info, prev.length);
		input[input.length - 1] = i;
		prev = await hmac(prk, input);
		out.set(prev.subarray(0, Math.min(prev.length, length - offset)), offset);
		offset += prev.length;
	}
	return out;
}

export interface SymmetricKey {
	enc: Uint8Array;
	mac: Uint8Array;
}

export const splitKey = (k: Uint8Array): SymmetricKey => ({ enc: k.slice(0, 32), mac: k.slice(32, 64) });

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let d = 0;
	for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
	return d === 0;
}

/** EncString type 2: AES-256-CBC + HMAC-SHA256 over iv || ciphertext. */
export async function encryptEncString(data: Uint8Array, key: SymmetricKey): Promise<string> {
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const k = await subtle.importKey("raw", bytes(key.enc), "AES-CBC", false, ["encrypt"]);
	const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, k, bytes(data)));
	const mac = await hmac(key.mac, new Uint8Array([...iv, ...ct]));
	return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

export async function decryptEncString(s: string, key: SymmetricKey): Promise<Uint8Array<ArrayBuffer>> {
	const m = /^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(s);
	if (!m) throw new Error("Unsupported EncString");
	const [iv, ct, mac] = [unb64(m[1]!), unb64(m[2]!), unb64(m[3]!)];
	if (!timingSafeEqual(await hmac(key.mac, new Uint8Array([...iv, ...ct])), mac)) throw new Error("EncString MAC mismatch");
	const k = await subtle.importKey("raw", bytes(key.enc), "AES-CBC", false, ["decrypt"]);
	return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv: bytes(iv) }, k, bytes(ct)));
}

export interface MasterKeys {
	masterPasswordHash: string;
	stretched: SymmetricKey;
}

export async function deriveMasterKeys(email: string, password: string, iterations: number): Promise<MasterKeys> {
	const pw = te.encode(password);
	const masterKey = await pbkdf2(pw, te.encode(normalizeEmail(email)), iterations);
	const hash = await pbkdf2(masterKey, pw, 1);
	const stretched = {
		enc: await hkdfExpand(masterKey, te.encode("enc"), 32),
		mac: await hkdfExpand(masterKey, te.encode("mac"), 32),
	};
	masterKey.fill(0);
	return { masterPasswordHash: b64(hash), stretched };
}

export interface RegisterBody {
	email: string;
	name: string;
	masterPasswordHash: string;
	key: string;
	kdf: 0;
	kdfIterations: number;
	keys: { publicKey: string; encryptedPrivateKey: string };
}

export interface Registration {
	body: RegisterBody;
	masterKeys: MasterKeys;
	/** Raw 64-byte user key, kept only to verify the server round-trip. */
	userKey: Uint8Array;
}

export async function makeRegistration(args: {
	email: string;
	name: string;
	password: string;
	iterations?: number;
}): Promise<Registration> {
	const email = normalizeEmail(args.email);
	const iterations = args.iterations ?? DEFAULT_KDF_ITERATIONS;
	const masterKeys = await deriveMasterKeys(email, args.password, iterations);
	const userKey = crypto.getRandomValues(new Uint8Array(64));
	const pair = await subtle.generateKey(
		{ name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
		true,
		["encrypt", "decrypt"],
	);
	const publicKey = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
	const privateKey = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
	const body: RegisterBody = {
		email,
		name: args.name,
		masterPasswordHash: masterKeys.masterPasswordHash,
		key: await encryptEncString(userKey, masterKeys.stretched),
		kdf: 0,
		kdfIterations: iterations,
		keys: { publicKey: b64(publicKey), encryptedPrivateKey: await encryptEncString(privateKey, splitKey(userKey)) },
	};
	privateKey.fill(0);
	return { body, masterKeys, userKey };
}
