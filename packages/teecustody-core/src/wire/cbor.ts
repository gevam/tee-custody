// Canonical CBOR codec: the single decode entry point (SR-3, ADR 0010).
import type { Bytes } from "../capabilities.js";
import { utf8DecodeStrict, utf8Encode } from "../encoding.js";
import { WireError, type CanonicalValue, type DecodeLimits, type WireErrorCode } from "./types.js";

const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;

function fail(code: WireErrorCode): never {
    throw new WireError(code);
}

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

const INTEGER_BOUND = 2n ** 64n;

function encodeInteger(writer: ByteWriter, integer: bigint): void {
    if (integer >= INTEGER_BOUND || integer < -INTEGER_BOUND) {
        fail("UNSUPPORTED_TYPE");
    }
    if (integer >= 0n) {
        writer.writeHead(MAJOR_UNSIGNED, integer);
    } else {
        writer.writeHead(MAJOR_NEGATIVE, -1n - integer);
    }
}

type EncodeTask = { readonly raw: Bytes } | { readonly value: unknown };

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
        } else if (typeof current === "number") {
            if (!Number.isSafeInteger(current) || Object.is(current, -0)) {
                fail("UNSUPPORTED_TYPE");
            }
            encodeInteger(writer, BigInt(current));
        } else if (typeof current === "bigint") {
            encodeInteger(writer, current);
        } else if (typeof current === "string") {
            encodeText(writer, current);
        } else if (current instanceof Uint8Array) {
            writer.writeHead(MAJOR_BYTES, current.length);
            writer.writeBytes(current);
        } else if (current instanceof Map) {
            const entries: { key: Bytes; value: unknown }[] = [];
            for (const [key, entryValue] of current as ReadonlyMap<unknown, unknown>) {
                if (typeof key !== "string") {
                    fail("UNSUPPORTED_TYPE");
                }
                const keyWriter = new ByteWriter();
                encodeText(keyWriter, key);
                entries.push({ key: keyWriter.finish(), value: entryValue });
            }
            entries.sort((a, b) => compareBytes(a.key, b.key));
            writer.writeHead(MAJOR_MAP, entries.length);
            for (const entry of entries.reverse()) {
                tasks.push({ value: entry.value }, { raw: entry.key });
            }
        } else if (Array.isArray(current)) {
            const items = current as readonly unknown[];
            writer.writeHead(MAJOR_ARRAY, items.length);
            for (let index = items.length - 1; index >= 0; index--) {
                tasks.push({ value: items[index] ?? null });
            }
        } else {
            fail("UNSUPPORTED_TYPE");
        }
    }
    return writer.finish();
}

interface ArrayFrame {
    readonly kind: "array";
    readonly depth: number;
    readonly items: CanonicalValue[];
    remaining: number;
}

interface MapFrame {
    readonly kind: "map";
    readonly depth: number;
    readonly entries: Map<string, CanonicalValue>;
    remaining: number;
    key: string | undefined;
    previousKey: Bytes | undefined;
    disordered: boolean;
}

type Frame = ArrayFrame | MapFrame;

// Smallest argument each additional-information width may carry in shortest form (rule 5c).
const SHORTEST_MINIMUM: readonly bigint[] = [24n, 0x100n, 0x10000n, 0x100000000n];

class Reader {
    position = 0;

    constructor(private readonly data: Bytes) {}

    get remaining(): number {
        return this.data.length - this.position;
    }

    byte(): number {
        if (this.position >= this.data.length) {
            fail("MALFORMED");
        }
        return this.data[this.position++] as number;
    }

    argument(info: number): bigint {
        if (info < 24) {
            return BigInt(info);
        }
        const width = 1 << (info - 24);
        if (width > this.remaining) {
            fail("MALFORMED");
        }
        let value = 0n;
        for (let count = width; count > 0; count--) {
            value = (value << 8n) | BigInt(this.byte());
        }
        return value;
    }

    view(start: number): Bytes {
        return this.data.subarray(start, this.position);
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

function sameBytes(a: Bytes, b: Bytes): boolean {
    return compareBytes(a, b) === 0;
}

function isPositiveSafeInteger(value: number): boolean {
    return Number.isSafeInteger(value) && value > 0;
}

// ints: number if safe, else bigint
export function decodeCanonical(data: Bytes, limits: DecodeLimits): CanonicalValue {
    if (
        !isPositiveSafeInteger(limits.maxBytes) ||
        !isPositiveSafeInteger(limits.maxDepth) ||
        !isPositiveSafeInteger(limits.maxItems)
    ) {
        throw new RangeError("INVALID_LIMITS");
    }
    if (data.length > limits.maxBytes) {
        fail("TOO_LARGE");
    }
    const maxItems = BigInt(limits.maxItems);
    const reader = new Reader(data);
    const stack: Frame[] = [];
    let itemsRead = 0n;
    for (;;) {
        const parent = stack.at(-1);
        const depth = parent === undefined ? 1 : parent.depth + 1;
        const isKey = parent?.kind === "map" && parent.key === undefined;
        const start = reader.position;
        const initial = reader.byte();
        const major = initial >> 5;
        const info = initial & 0x1f;
        // (a) reserved additional information, and 31 where it cannot mean "indefinite".
        if ((info >= 28 && info <= 30) || (info === 31 && (major <= 1 || major >= 6))) {
            fail("MALFORMED");
        }
        // (b) argument bytes present; two-byte simple values below 32 are not well-formed.
        const argument = info === 31 ? 0n : reader.argument(info);
        if (major === MAJOR_SIMPLE && info === 24 && argument < 32n) {
            fail("MALFORMED");
        }
        // (c) shortest form, major types 0-6 only.
        if (
            major !== MAJOR_SIMPLE &&
            info >= 24 &&
            argument < (SHORTEST_MINIMUM[info - 24] ?? 0n)
        ) {
            fail("NONCANONICAL");
        }
        // (d) indefinite lengths, then types outside the data model.
        if (info === 31) {
            fail("NONCANONICAL");
        }
        if (major === MAJOR_TAG || (major === MAJOR_SIMPLE && (info < 20 || info > 22))) {
            fail("UNSUPPORTED_TYPE");
        }
        if (isKey && major !== MAJOR_TEXT) {
            fail("UNSUPPORTED_TYPE");
        }
        // (e) depth.
        if (depth > limits.maxDepth) {
            fail("LIMIT_EXCEEDED");
        }
        // (f) item budget, then declared sizes against the remaining input; nothing allocated before.
        itemsRead += 1n;
        const children =
            major === MAJOR_ARRAY ? argument : major === MAJOR_MAP ? 2n * argument : 0n;
        if (itemsRead + children > maxItems) {
            fail("LIMIT_EXCEEDED");
        }
        const declared = major === MAJOR_BYTES || major === MAJOR_TEXT ? argument : children;
        if (declared > BigInt(reader.remaining)) {
            fail("MALFORMED");
        }
        let value: CanonicalValue;
        if (major === MAJOR_UNSIGNED) {
            value = integerValue(argument);
        } else if (major === MAJOR_NEGATIVE) {
            value = integerValue(-1n - argument);
        } else if (major === MAJOR_BYTES) {
            value = reader.take(Number(argument));
        } else if (major === MAJOR_TEXT) {
            try {
                value = utf8DecodeStrict(reader.take(Number(argument)));
            } catch {
                fail("MALFORMED");
            }
        } else if (major === MAJOR_ARRAY && argument > 0n) {
            stack.push({ kind: "array", depth, items: [], remaining: Number(argument) });
            continue;
        } else if (major === MAJOR_ARRAY) {
            value = Object.freeze([]);
        } else if (major === MAJOR_MAP && argument > 0n) {
            stack.push({
                kind: "map",
                depth,
                entries: new Map(),
                remaining: Number(argument),
                key: undefined,
                previousKey: undefined,
                disordered: false,
            });
            continue;
        } else if (major === MAJOR_MAP) {
            value = new Map();
        } else {
            value = info === 20 ? false : info === 21 ? true : null;
        }
        for (;;) {
            const frame = stack.at(-1);
            if (frame === undefined) {
                if (reader.remaining !== 0) {
                    fail("MALFORMED");
                }
                // Rule 4 backstop: the scan above already enforces every canonical-form rule, so a
                // mismatch here is unreachable unless that scan regresses.
                /* v8 ignore next 3 */
                if (!sameBytes(encodeCanonical(value), data)) {
                    fail("NONCANONICAL");
                }
                return value;
            }
            if (frame.kind === "map" && frame.key === undefined) {
                const keyBytes = reader.view(start);
                if (
                    frame.previousKey !== undefined &&
                    compareBytes(frame.previousKey, keyBytes) >= 0
                ) {
                    frame.disordered = true;
                }
                frame.previousKey = keyBytes;
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
            if (frame.kind === "map" && frame.disordered) {
                fail("NONCANONICAL");
            }
            value = frame.kind === "map" ? frame.entries : Object.freeze(frame.items);
        }
    }
}
