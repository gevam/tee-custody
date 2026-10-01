// T-09 criterion 12 (SR-3): mutation fuzz seeded from every valid case of canonical-cbor.json.
// Case count: TEECUSTODY_CBOR_FUZZ_CASES (default 2,000; the scheduled T-14 job sets 100,000).
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

import { describe, expect, it } from "vitest";

import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import { WireError, type DecodeLimits } from "../../src/wire/types.js";

interface CodecVectors {
    readonly limits: {
        readonly max_bytes: number;
        readonly max_depth: number;
        readonly max_items: number;
    };
    readonly valid: readonly { readonly id: string; readonly hex: string }[];
}

const SEED = 0x7090f22;
const DEFAULT_CASES = 2000;
const PER_INPUT_BUDGET_MS = 50;

const VECTORS_URL = new URL("../../../../spec/vectors/wire/canonical-cbor.json", import.meta.url);
const vectors = JSON.parse(readFileSync(VECTORS_URL, "utf8")) as CodecVectors;
const limits: DecodeLimits = {
    maxBytes: vectors.limits.max_bytes,
    maxDepth: vectors.limits.max_depth,
    maxItems: vectors.limits.max_items,
};
const seeds = vectors.valid.map((vector) => new Uint8Array(Buffer.from(vector.hex, "hex")));

function caseCount(): number {
    const configured = process.env["TEECUSTODY_CBOR_FUZZ_CASES"];
    if (configured === undefined || configured === "") {
        return DEFAULT_CASES;
    }
    const count = Number(configured);
    if (!Number.isSafeInteger(count) || count <= 0) {
        throw new Error("TEECUSTODY_CBOR_FUZZ_CASES must be a positive integer");
    }
    return count;
}

// mulberry32: deterministic, so a failing case reproduces from SEED and its index.
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

type Mutation = (input: Uint8Array, pick: (below: number) => number) => Uint8Array;

const MUTATIONS: readonly (readonly [string, Mutation])[] = [
    [
        "bit flip",
        (input, pick) => {
            const out = input.slice();
            if (out.length > 0) {
                const index = pick(out.length);
                out[index] = (out[index] as number) ^ (1 << pick(8));
            }
            return out;
        },
    ],
    [
        "byte insert",
        (input, pick) => {
            const index = pick(input.length + 1);
            return Uint8Array.of(...input.subarray(0, index), pick(256), ...input.subarray(index));
        },
    ],
    [
        "byte delete",
        (input, pick) => {
            const index = pick(input.length);
            return Uint8Array.of(...input.subarray(0, index), ...input.subarray(index + 1));
        },
    ],
    ["truncation", (input, pick) => input.slice(0, pick(input.length))],
    [
        "header substitution",
        (input, pick) => {
            const out = input.slice();
            if (out.length > 0) {
                // Same position, a different major type and additional information.
                out[pick(out.length)] = (pick(8) << 5) | pick(32);
            }
            return out;
        },
    ],
];

function hex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

describe("canonical CBOR mutation fuzz (criterion 12, SR-3)", () => {
    const cases = caseCount();

    it(`every one of ${String(cases)} mutated inputs re-encodes identically or throws WireError within ${String(PER_INPUT_BUDGET_MS)} ms`, () => {
        const random = prng(SEED);
        const pick = (below: number): number => Math.floor(random() * below);
        const used = new Set<string>();
        for (let index = 0; index < cases; index++) {
            const seed = seeds[index % seeds.length] as Uint8Array;
            const [name, mutate] = MUTATIONS[pick(MUTATIONS.length)] as (typeof MUTATIONS)[number];
            used.add(name);
            const input = mutate(seed, pick);
            const label = `case ${String(index)} (${name}): ${hex(input).slice(0, 64)}`;
            const started = performance.now();
            try {
                const decoded = decodeCanonical(input, limits);
                expect(hex(encodeCanonical(decoded)), label).toBe(hex(input));
            } catch (error) {
                expect(error, label).toBeInstanceOf(WireError);
            }
            expect(performance.now() - started, label).toBeLessThan(PER_INPUT_BUDGET_MS);
        }
        expect(used.size).toBe(Math.min(MUTATIONS.length, cases));
    });
});
