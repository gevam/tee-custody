// T-09 criteria 7-8: property tests with a hand-written seeded generator (no new dependency).
import { describe, expect, it } from "vitest";

import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import { WireError, type CanonicalValue, type DecodeLimits } from "../../src/wire/types.js";

const CASES = 600;
const ROOMY: DecodeLimits = { maxBytes: 1_000_000, maxDepth: 64, maxItems: 1_000_000 };
const VECTOR_LIMITS: DecodeLimits = { maxBytes: 1024, maxDepth: 4, maxItems: 64 };

// mulberry32: small deterministic PRNG, so every failure reproduces from its seed.
function prng(seed: number): () => number {
    let state = seed >>> 0;
    return () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

class Generator {
    constructor(private readonly random: () => number) {}

    int(below: number): number {
        return Math.floor(this.random() * below);
    }

    bigintBits(bits: number): bigint {
        let value = 0n;
        for (let index = 0; index < bits; index++) {
            value = (value << 1n) | BigInt(this.int(2));
        }
        return value;
    }

    integer(): number | bigint {
        const magnitude = this.bigintBits(this.int(65));
        const value = this.int(2) === 0 ? magnitude : -1n - magnitude;
        const asNumber = Number(value);
        return Number.isSafeInteger(asNumber) ? asNumber : value;
    }

    codePoint(): number {
        switch (this.int(4)) {
            case 0:
                return this.int(0x80);
            case 1:
                return 0x80 + this.int(0xd800 - 0x80);
            case 2:
                return 0xe000 + this.int(0x10000 - 0xe000);
            default:
                return 0x10000 + this.int(0x110000 - 0x10000);
        }
    }

    text(): string {
        const points: number[] = [];
        for (let count = this.int(8); count > 0; count--) {
            points.push(this.codePoint());
        }
        return String.fromCodePoint(...points);
    }

    bytes(): Uint8Array {
        const out = new Uint8Array(this.int(40));
        for (let index = 0; index < out.length; index++) {
            out[index] = this.int(256);
        }
        return out;
    }

    value(depth: number): CanonicalValue {
        const kinds = depth >= 5 ? 6 : 8;
        switch (this.int(kinds)) {
            case 0:
                return null;
            case 1:
                return this.int(2) === 0;
            case 2:
                return this.integer();
            case 3:
            case 4:
                return this.text();
            case 5:
                return this.bytes();
            case 6: {
                const items: CanonicalValue[] = [];
                for (let count = this.int(6); count > 0; count--) {
                    items.push(this.value(depth + 1));
                }
                return items;
            }
            default: {
                const entries = new Map<string, CanonicalValue>();
                for (let count = this.int(6); count > 0; count--) {
                    entries.set(this.text(), this.value(depth + 1));
                }
                return entries;
            }
        }
    }
}

const MAX_DEPTH = 64;

// Rule-5 depth: top level 1; array elements and map values are their container's depth + 1.
function depthOf(value: CanonicalValue): number {
    if (value instanceof Map) {
        const children = [...(value as ReadonlyMap<string, CanonicalValue>).values()];
        return 1 + Math.max(0, ...children.map(depthOf));
    }
    if (Array.isArray(value)) {
        return 1 + Math.max(0, ...(value as readonly CanonicalValue[]).map(depthOf));
    }
    return 1;
}

// Wraps a value in single-entry arrays and maps up to `layers` deep, reaching the shared ceiling.
function deepen(value: CanonicalValue, layers: number, generator: Generator): CanonicalValue {
    let current = value;
    for (let layer = 0; layer < layers; layer++) {
        current = generator.int(2) === 0 ? [current] : new Map([[generator.text(), current]]);
    }
    return current;
}

// Rebuilds a value with every map's insertion order reversed; encoding must not depend on it.
function reorder(value: CanonicalValue): CanonicalValue {
    if (value instanceof Map) {
        const entries = [...(value as ReadonlyMap<string, CanonicalValue>)].reverse();
        return new Map(entries.map(([key, entry]) => [key, reorder(entry)]));
    }
    if (Array.isArray(value)) {
        return (value as readonly CanonicalValue[]).map(reorder);
    }
    return value;
}

describe("encode/decode properties (criterion 7)", () => {
    it(`round-trips ${String(CASES)} generated values and encodes deterministically`, () => {
        const generator = new Generator(prng(0x7e09));
        let maxSeen = 0;
        for (let index = 0; index < CASES; index++) {
            const shallow = generator.value(1);
            const room = MAX_DEPTH - depthOf(shallow);
            const value =
                index % 4 === 0 ? deepen(shallow, room - generator.int(3), generator) : shallow;
            expect(depthOf(value)).toBeLessThanOrEqual(MAX_DEPTH);
            maxSeen = Math.max(maxSeen, depthOf(value));
            const encoded = encodeCanonical(value);
            expect(decodeCanonical(encoded, ROOMY), `case ${String(index)}`).toEqual(value);
            expect(encodeCanonical(value), `case ${String(index)}`).toEqual(encoded);
            expect(encodeCanonical(reorder(value)), `case ${String(index)}`).toEqual(encoded);
        }
        expect(maxSeen).toBe(MAX_DEPTH);
    });
});

describe("decoder totality on arbitrary bytes (criterion 8, SR-3)", () => {
    it(`returns or throws WireError for ${String(CASES)} random inputs of at most 256 bytes`, () => {
        const generator = new Generator(prng(0x5e3));
        for (let index = 0; index < CASES; index++) {
            const input = new Uint8Array(generator.int(257));
            for (let offset = 0; offset < input.length; offset++) {
                input[offset] = generator.int(256);
            }
            try {
                decodeCanonical(input, VECTOR_LIMITS);
            } catch (error) {
                expect(error, `case ${String(index)}`).toBeInstanceOf(WireError);
            }
        }
    });
});
