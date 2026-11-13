// Minimal protobuf wire-format reader/writer: varint (0) and length-delimited (2) fields only,
// which is all the Google Authenticator migration payload uses.

export interface Field {
	no: number;
	wire: 0 | 2;
	/** varint as BigInt (wire 0) or raw bytes (wire 2). */
	value: bigint | Uint8Array;
}

export class ProtobufError extends Error {
	override name = "ProtobufError";
}

export function decodeFields(buf: Uint8Array): Field[] {
	const fields: Field[] = [];
	let pos = 0;
	const varint = (): bigint => {
		let result = 0n;
		let shift = 0n;
		for (;;) {
			if (pos >= buf.length) throw new ProtobufError("Truncated varint");
			const b = buf[pos++]!;
			result |= BigInt(b & 0x7f) << shift;
			if ((b & 0x80) === 0) return result;
			shift += 7n;
			if (shift > 63n) throw new ProtobufError("Varint too long");
		}
	};
	while (pos < buf.length) {
		const key = Number(varint());
		const no = key >>> 3;
		const wire = key & 7;
		if (wire === 0) fields.push({ no, wire, value: varint() });
		else if (wire === 2) {
			const len = Number(varint());
			if (pos + len > buf.length) throw new ProtobufError("Truncated field");
			fields.push({ no, wire, value: buf.subarray(pos, pos + len) });
			pos += len;
		} else if (wire === 1) pos += 8;
		else if (wire === 5) pos += 4;
		else throw new ProtobufError(`Unsupported wire type ${wire}`);
	}
	return fields;
}

/** Interpret a varint as a signed 64-bit integer (protobuf int32/int64), as a Number. */
export function toSigned(v: bigint): number {
	return Number(BigInt.asIntN(64, v));
}

function encodeVarint(v: bigint, out: number[]): void {
	let x = BigInt.asUintN(64, v);
	while (x >= 0x80n) {
		out.push(Number((x & 0x7fn) | 0x80n));
		x >>= 7n;
	}
	out.push(Number(x));
}

export class Writer {
	private out: number[] = [];
	varint(no: number, v: number | bigint): this {
		encodeVarint(BigInt((no << 3) | 0), this.out);
		encodeVarint(BigInt(v), this.out);
		return this;
	}
	bytes(no: number, b: Uint8Array): this {
		encodeVarint(BigInt((no << 3) | 2), this.out);
		encodeVarint(BigInt(b.length), this.out);
		for (const x of b) this.out.push(x);
		return this;
	}
	string(no: number, s: string): this {
		return this.bytes(no, new TextEncoder().encode(s));
	}
	finish(): Uint8Array {
		return new Uint8Array(this.out);
	}
}
