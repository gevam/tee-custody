// Canonical CBOR codec: the single decode entry point (SR-3, ADR 0010).
import type { Bytes } from "../capabilities.js";
import { utf8DecodeStrict, utf8Encode } from "../encoding.js";
import type { CanonicalValue, DecodeLimits } from "./types.js";

const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

const SIMPLE_FALSE = 20n;
const SIMPLE_TRUE = 21n;

class ByteWriter {
    private buffer = new Uint8Array(64);
    private length = 0;

    private reserve(extra: number): void {
        if (this.length + extra > this.buffer.length) {
            const grown = new Uint8Array(Math.max(this.buffer.length * 2, this.length + extra));
            grown.set(this.buffer.subarray(0, this.length));
            this.buffer = grown;
        }
    }

    writeByte(byte: number): void {
        this.reserve(1);
        this.buffer[this.length++] = byte;
    }

    writeBytes(bytes: Bytes): void {
        this.reserve(bytes.length);
        this.buffer.set(bytes, this.length);
        this.length += bytes.length;
    }

    writeHead(major: number, argument: number | bigint): void {
        const head = major << 5;
        const arg = BigInt(argument);
        if (arg < 24n) {
            this.writeByte(head | Number(arg));
            return;
        }
        const width = arg < 0x100n ? 1 : arg < 0x10000n ? 2 : arg < 0x100000000n ? 4 : 8;
        this.writeByte(head | (24 + Math.log2(width)));
        for (let shift = BigInt((width - 1) * 8); shift >= 0n; shift -= 8n) {
            this.writeByte(Number((arg >> shift) & 0xffn));
        }
    }

    finish(): Bytes {
        return this.buffer.slice(0, this.length);
    }
}

function compareBytes(a: Bytes, b: Bytes): number {
    const shared = Math.min(a.length, b.length);
    for (let index = 0; index < shared; index++) {
        const difference = (a[index] ?? 0) - (b[index] ?? 0);
        if (difference !== 0) {
            return difference;
        }
    }
    return a.length - b.length;
}

function encodeText(writer: ByteWriter, text: string): void {
    const bytes = utf8Encode(text);
    writer.writeHead(MAJOR_TEXT, bytes.length);
    writer.writeBytes(bytes);
}

type EncodeTask = { readonly raw: Bytes } | { readonly value: CanonicalValue };

export function encodeCanonical(value: CanonicalValue): Bytes {
    const writer = new ByteWriter();
    const tasks: EncodeTask[] = [{ value }];
    for (let task = tasks.pop(); task !== undefined; task = tasks.pop()) {
        if ("raw" in task) {
            writer.writeBytes(task.raw);
            continue;
        }
        const current = task.value;
        if (current === null) {
            writer.writeByte(0xf6);
        } else if (typeof current === "boolean") {
            writer.writeByte(current ? 0xf5 : 0xf4);
        } else if (typeof current === "number" || typeof current === "bigint") {
            const integer = BigInt(current);
            if (integer >= 0n) {
                writer.writeHead(MAJOR_UNSIGNED, integer);
            } else {
                writer.writeHead(MAJOR_NEGATIVE, -1n - integer);
            }
        } else if (typeof current === "string") {
            encodeText(writer, current);
        } else if (current instanceof Uint8Array) {
            writer.writeHead(MAJOR_BYTES, current.length);
            writer.writeBytes(current);
        } else if (current instanceof Map) {
            const entries: { key: Bytes; value: CanonicalValue }[] = [];
            for (const [key, entryValue] of current as ReadonlyMap<string, CanonicalValue>) {
                const keyWriter = new ByteWriter();
                encodeText(keyWriter, key);
                entries.push({ key: keyWriter.finish(), value: entryValue });
            }
            entries.sort((a, b) => compareBytes(a.key, b.key));
            writer.writeHead(MAJOR_MAP, entries.length);
            for (let index = entries.length - 1; index >= 0; index--) {
                const entry = entries[index];
                if (entry !== undefined) {
                    tasks.push({ value: entry.value }, { raw: entry.key });
                }
            }
        } else {
            const items = current as readonly CanonicalValue[];
            writer.writeHead(MAJOR_ARRAY, items.length);
            for (let index = items.length - 1; index >= 0; index--) {
                tasks.push({ value: items[index] ?? null });
            }
        }
    }
    return writer.finish();
}

interface ArrayFrame {
    readonly kind: "array";
    readonly items: CanonicalValue[];
    remaining: number;
}

interface MapFrame {
    readonly kind: "map";
    readonly entries: Map<string, CanonicalValue>;
    remaining: number;
    key: string | undefined;
}

type Frame = ArrayFrame | MapFrame;

class Reader {
    position = 0;

    constructor(private readonly data: Bytes) {}

    byte(): number {
        return this.data[this.position++] ?? 0;
    }

    argument(info: number): bigint {
        if (info < 24) {
            return BigInt(info);
        }
        let value = 0n;
        for (let count = 1 << (info - 24); count > 0; count--) {
            value = (value << 8n) | BigInt(this.byte());
        }
        return value;
    }

    take(length: number): Bytes {
        const start = this.position;
        this.position += length;
        return this.data.slice(start, this.position);
    }
}

function integerValue(value: bigint): number | bigint {
    const asNumber = Number(value);
    return Number.isSafeInteger(asNumber) ? asNumber : value;
}

// ints: number if safe, else bigint
export function decodeCanonical(data: Bytes, limits: DecodeLimits): CanonicalValue {
    const reader = new Reader(data);
    const stack: Frame[] = [];
    for (;;) {
        const initial = reader.byte();
        const major = initial >> 5;
        const argument = reader.argument(initial & 0x1f);
        let value: CanonicalValue;
        if (major === MAJOR_UNSIGNED) {
            value = integerValue(argument);
        } else if (major === MAJOR_NEGATIVE) {
            value = integerValue(-1n - argument);
        } else if (major === MAJOR_BYTES) {
            value = reader.take(Number(argument));
        } else if (major === MAJOR_TEXT) {
            value = utf8DecodeStrict(reader.take(Number(argument)));
        } else if (major === MAJOR_ARRAY && argument > 0n) {
            stack.push({ kind: "array", items: [], remaining: Number(argument) });
            continue;
        } else if (major === MAJOR_ARRAY) {
            value = Object.freeze([]);
        } else if (major === MAJOR_MAP && argument > 0n) {
            stack.push({
                kind: "map",
                entries: new Map(),
                remaining: Number(argument),
                key: undefined,
            });
            continue;
        } else if (major === MAJOR_MAP) {
            value = new Map();
        } else if (major === MAJOR_SIMPLE && argument === SIMPLE_FALSE) {
            value = false;
        } else if (major === MAJOR_SIMPLE && argument === SIMPLE_TRUE) {
            value = true;
        } else {
            value = null;
        }
        for (;;) {
            const frame = stack.at(-1);
            if (frame === undefined) {
                return value;
            }
            if (frame.kind === "map" && frame.key === undefined) {
                frame.key = value as string;
                break;
            }
            if (frame.kind === "map") {
                frame.entries.set(frame.key as string, value);
                frame.key = undefined;
            } else {
                frame.items.push(value);
            }
            frame.remaining--;
            if (frame.remaining > 0) {
                break;
            }
            stack.pop();
            value = frame.kind === "map" ? frame.entries : Object.freeze(frame.items);
        }
    }
}
