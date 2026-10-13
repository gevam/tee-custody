// T-16 criterion 11 (SR-3): 2,000 seeded mutations of a valid bundle. verifyBundle either resolves or throws
// BundleError, never anything else, and each call finishes within the budget. verifyAttestation is mocked (A1).
import { performance } from "node:perf_hooks";

import { beforeAll, describe, expect, it, vi } from "vitest";

import type { TrustProfile } from "../../src/attestation/types.js";
import { verifyAttestation } from "../../src/attestation/verify.js";
import { BundleError } from "../../src/bundle/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import type { SecurityEventSink } from "../../src/capabilities.js";
import { encodeCanonical } from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import {
    INSTANCE,
    attestation,
    bundleDeps,
    bundleMap,
    identity,
    standardEntries,
} from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

const SEED = 0x7160b0d;
const CASES = 2000;
const PER_CASE_BUDGET_MS = 200;
const profile = {} as TrustProfile;
const events: SecurityEventSink = { report: () => Promise.resolve() };

// mulberry32: deterministic, so a failing case reproduces from SEED and its index.
function prng(seed: number): (below: number) => number {
    let state = seed >>> 0;
    return (below) => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * below);
    };
}

type Pick = (below: number) => number;
type BundleMap = Map<string, CanonicalValue>;

const INTERESTING_BYTES = [
    0x00, 0x01, 0x17, 0x18, 0x1b, 0x1f, 0x40, 0x5f, 0x7f, 0x80, 0xa0, 0xbf, 0xf6, 0xff,
];

function randomValue(pick: Pick): CanonicalValue {
    const choices: CanonicalValue[] = [
        null,
        true,
        -1,
        0,
        2 ** 32,
        Number.MAX_SAFE_INTEGER,
        2n ** 53n,
        2n ** 64n - 1n,
        -(2n ** 64n),
        "",
        "B2".repeat(16),
        new Uint8Array(pick(70)),
        [],
        new Map<string, CanonicalValue>(),
    ];
    return choices[pick(choices.length)] ?? null;
}

function byteMutation(input: Uint8Array, pick: Pick): Uint8Array {
    const out = input.slice();
    const index = pick(out.length);
    switch (pick(5)) {
        case 0:
            out[index] = (out[index] as number) ^ (1 << pick(8));
            return out;
        case 1:
            out[index] = INTERESTING_BYTES[pick(INTERESTING_BYTES.length)] as number;
            return out;
        case 2:
            return Uint8Array.of(...out.subarray(0, index), pick(256), ...out.subarray(index));
        case 3:
            return Uint8Array.of(...out.subarray(0, index), ...out.subarray(index + 1));
        default:
            return out.subarray(0, index);
    }
}

function valueMutation(base: BundleMap, pick: Pick): Uint8Array {
    const map = new Map(base);
    const prekeys: CanonicalValue[] = (map.get("prekeys") as BundleMap[]).map((e) => new Map(e));
    map.set("prekeys", prekeys);
    if (pick(5) === 0) {
        // replace a whole entry, or the bundle itself, with a value of another type
        if (pick(4) === 0) {
            return encodeCanonical(randomValue(pick));
        }
        prekeys[pick(prekeys.length)] = randomValue(pick);
        return encodeCanonical(map);
    }
    const target = pick(2) === 0 ? map : (prekeys[pick(prekeys.length)] as BundleMap);
    const keys = [...target.keys()];
    if (pick(4) === 0) {
        target.delete(keys[pick(keys.length)] as string);
    } else {
        target.set(keys[pick(keys.length)] as string, randomValue(pick));
    }
    return encodeCanonical(map);
}

describe("verifyBundle mutation fuzz (11)", () => {
    let base: BundleMap;
    let valid: Uint8Array;

    beforeAll(async () => {
        vi.mocked(verifyAttestation).mockImplementation(() => Promise.resolve(attestation()));
        base = await bundleMap({ ik: await identity(), entries: standardEntries() });
        valid = encodeCanonical(base);
    });

    it(`throws only BundleError on ${String(CASES)} seeded mutations, each within budget`, async () => {
        const pick = prng(SEED);
        const deps = bundleDeps();
        let rejected = 0;
        for (let index = 0; index < CASES; index++) {
            const input = pick(2) === 0 ? byteMutation(valid, pick) : valueMutation(base, pick);
            const started = performance.now();
            const outcome = await verifyBundle(
                { instanceId: INSTANCE, bundle: input },
                profile,
                events,
                deps,
            ).then(
                () => undefined,
                (error: unknown) => error,
            );
            const elapsed = performance.now() - started;
            if (outcome !== undefined && !(outcome instanceof BundleError)) {
                const detail =
                    outcome instanceof Error
                        ? `${outcome.name}: ${outcome.message}`
                        : typeof outcome;
                expect.fail(`case ${String(index)}: ${detail}`);
            }
            if (outcome !== undefined) {
                rejected++;
            }
            expect(elapsed, `case ${String(index)}`).toBeLessThan(PER_CASE_BUDGET_MS);
        }
        expect(rejected).toBeGreaterThan(CASES / 2);
    });
});
