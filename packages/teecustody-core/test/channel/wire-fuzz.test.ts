// T-15 criterion 9 (SR-3): seeded mutation fuzz of decodeResponse. Every mutated response either decodes
// to an envelope that re-encodes to exactly the input, or throws WireError; each call stays under 50 ms.
import { performance } from "node:perf_hooks";

import { describe, expect, it } from "vitest";

import {
    decodeResponse,
    type FrameResultEnvelope,
    type OpenResultEnvelope,
} from "../../src/channel/wire.js";
import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import { WireError, type CanonicalValue } from "../../src/wire/types.js";

const SEED = 0x7015;
const CASES = 5000;
const PER_CALL_BUDGET_MS = 50;
const ENVELOPE_LIMITS = { maxBytes: 65_536, maxDepth: 2, maxItems: 16 };
const AAD_LIMITS = { maxBytes: 512, maxDepth: 2, maxItems: 16 };

const SID = new Uint8Array(16).fill(7);
const RID = new Uint8Array(16).fill(9);

const cborMap = (entries: Record<string, CanonicalValue>): Uint8Array =>
    encodeCanonical(new Map(Object.entries(entries)));

interface Seed {
    readonly kind: "open_result" | "frame_result";
    readonly aad: Uint8Array;
    readonly ct: Uint8Array;
}

const SEEDS: readonly Seed[] = [
    {
        kind: "open_result",
        aad: cborMap({ session_id: SID, request_id: RID, seq: 0 }),
        ct: new Uint8Array(16).fill(1),
    },
    {
        kind: "open_result",
        aad: cborMap({ session_id: null, request_id: RID, seq: 0 }),
        ct: new Uint8Array(40).fill(2),
    },
    {
        kind: "frame_result",
        aad: cborMap({ session_id: SID, seq: 1, op: "test.echo" }),
        ct: new Uint8Array(24).fill(3),
    },
    {
        kind: "frame_result",
        aad: cborMap({ session_id: SID, seq: 2 ** 53 - 1, op: "a" }),
        ct: new Uint8Array(300).fill(4),
    },
];

const envelope = (seed: Seed, aad = seed.aad): Uint8Array =>
    cborMap({ kind: seed.kind, aad, ct: seed.ct });

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

type Pick = (below: number) => number;
type ByteMutation = (input: Uint8Array, pick: Pick) => Uint8Array;

const BYTE_MUTATIONS: readonly (readonly [string, ByteMutation])[] = [
    [
        "bit flip",
        (input, pick) => {
            const out = input.slice();
            const index = pick(out.length);
            out[index] = (out[index] as number) ^ (1 << pick(8));
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
            out[pick(out.length)] = (pick(8) << 5) | pick(32);
            return out;
        },
    ],
];

// Values a field (or the whole aad) is replaced with: right and wrong types, bounds, R-1 bigints.
const SUBSTITUTES: readonly CanonicalValue[] = [
    0,
    1,
    -1,
    2 ** 53 - 1,
    2n ** 53n,
    "",
    "a",
    "test.echo",
    "Test",
    null,
    true,
    new Uint8Array(15),
    new Uint8Array(16),
    new Uint8Array(17),
    [],
    [0],
    new Map(),
];

type StructuralMutation = (fields: Map<string, CanonicalValue>, pick: Pick) => CanonicalValue;

const substitute = (pick: Pick): CanonicalValue => SUBSTITUTES[pick(SUBSTITUTES.length)] ?? null;
const someKey = (fields: Map<string, CanonicalValue>, pick: Pick): string =>
    [...fields.keys()][pick(fields.size)] ?? "";

const STRUCTURAL_MUTATIONS: readonly (readonly [string, StructuralMutation])[] = [
    ["aad not a map", (_fields, pick) => substitute(pick)],
    ["field replaced", (fields, pick) => fields.set(someKey(fields, pick), substitute(pick))],
    [
        "field removed",
        (fields, pick) => {
            fields.delete(someKey(fields, pick));
            return fields;
        },
    ],
    [
        "key added",
        (fields, pick) =>
            fields.set(["x", "op", "request_id", "kind"][pick(4)] ?? "", substitute(pick)),
    ],
];

// Three modes: byte mutations of the whole envelope (outer decode); byte mutations of the nested aad
// re-wrapped in a canonical envelope (aad decode); structural changes to a canonical aad (schema checks).
function mutate(seed: Seed, pick: Pick): { readonly name: string; readonly input: Uint8Array } {
    const mode = pick(3);
    if (mode === 2) {
        const [name, mutation] = STRUCTURAL_MUTATIONS[
            pick(STRUCTURAL_MUTATIONS.length)
        ] as (typeof STRUCTURAL_MUTATIONS)[number];
        const fields = new Map(
            decodeCanonical(seed.aad, AAD_LIMITS) as ReadonlyMap<string, CanonicalValue>,
        );
        return { name, input: envelope(seed, encodeCanonical(mutation(fields, pick))) };
    }
    const [name, mutation] = BYTE_MUTATIONS[
        pick(BYTE_MUTATIONS.length)
    ] as (typeof BYTE_MUTATIONS)[number];
    if (mode === 0) {
        return { name: `envelope ${name}`, input: mutation(envelope(seed), pick) };
    }
    return { name: `aad ${name}`, input: envelope(seed, mutation(seed.aad, pick)) };
}

// The CDDL aad rebuilt from the decoded fields: it must be exactly the authenticated aad bytes.
function encodeAad(got: OpenResultEnvelope | FrameResultEnvelope): Uint8Array {
    return got.kind === "open_result"
        ? cborMap({ session_id: got.aad.sessionId, request_id: got.aad.requestId, seq: 0 })
        : cborMap({ session_id: got.aad.sessionId, seq: got.aad.seq, op: got.aad.op });
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

describe("criterion 9: decodeResponse mutation fuzz (SR-3)", () => {
    it("decodes every seed unmutated", () => {
        for (const seed of SEEDS) {
            expect(decodeResponse(envelope(seed), ENVELOPE_LIMITS, AAD_LIMITS).kind).toBe(
                seed.kind,
            );
        }
    });

    it(`each of ${String(CASES)} mutated responses round-trips or throws WireError within ${String(PER_CALL_BUDGET_MS)} ms`, () => {
        const random = prng(SEED);
        const pick: Pick = (below) => Math.floor(random() * below);
        const outcomes = { decoded: 0, rejected: 0 };
        const used = new Set<string>();
        for (let index = 0; index < CASES; index++) {
            const seed = SEEDS[index % SEEDS.length] as Seed;
            const { name, input } = mutate(seed, pick);
            used.add(name);
            const label = `case ${String(index)} (${name}): ${hex(input).slice(0, 96)}`;
            let got: OpenResultEnvelope | FrameResultEnvelope | undefined;
            let thrown: unknown;
            const started = performance.now();
            try {
                got = decodeResponse(input, ENVELOPE_LIMITS, AAD_LIMITS);
            } catch (error) {
                thrown = error;
            }
            expect(performance.now() - started, label).toBeLessThan(PER_CALL_BUDGET_MS);
            if (got === undefined) {
                expect(thrown, label).toBeInstanceOf(WireError);
                outcomes.rejected++;
            } else {
                const reencoded = cborMap({ kind: got.kind, aad: got.aadBytes, ct: got.ct });
                expect(hex(reencoded), label).toBe(hex(input));
                expect(hex(encodeAad(got)), label).toBe(hex(got.aadBytes));
                outcomes.decoded++;
            }
        }
        expect(used.size).toBe(2 * BYTE_MUTATIONS.length + STRUCTURAL_MUTATIONS.length);
        expect(outcomes.decoded).toBeGreaterThan(CASES / 20);
        expect(outcomes.rejected).toBeGreaterThan(CASES / 2);
    });
});
