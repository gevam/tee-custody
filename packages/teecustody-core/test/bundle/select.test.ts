// T-16 pre-key selection (INC-2-API §7.2; D2-4; SR-1): uniform over unused keys with a 5 s expiry margin.
import { describe, expect, it, vi } from "vitest";

import { createVerifiedBundle, type VerifiedBundle } from "../../src/bundle/types.js";
import { selectPreKey } from "../../src/bundle/select.js";
import type { Bytes } from "../../src/capabilities.js";
import { NOW_MS, attestation, pubFor } from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

const FAR = NOW_MS + 3_600_000;

function bundleWith(prekeys: readonly { id: number; notAfterMs: number }[]): VerifiedBundle {
    return createVerifiedBundle({
        instanceId: "b2".repeat(16),
        identityPublicKey: new Uint8Array(32).fill(9),
        attestation: attestation(),
        prekeys: prekeys.map((p) => ({ ...p, publicKey: pubFor(p.id) })),
        verifiedAtMs: NOW_MS,
    });
}

// Deterministic byte stream (splitmix32) so the statistical test cannot flake.
function seededRandomBytes(seed: number): (length: number) => Bytes {
    let state = seed >>> 0;
    const next = (): number => {
        state = (state + 0x9e3779b9) >>> 0;
        let z = state;
        z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
        z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
        return (z ^ (z >>> 16)) >>> 0;
    };
    return (length) => {
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            out[i] = next() & 0xff;
        }
        return out;
    };
}

function scriptedRandomBytes(values: readonly number[]): (length: number) => Bytes {
    const queue = [...values];
    return (length) => {
        const out = new Uint8Array(length);
        new DataView(out.buffer).setUint32(0, queue.shift() ?? 0);
        return out;
    };
}

describe("selectPreKey", () => {
    it("(10) never returns a used key or one at notAfterMs = now + 5000; draws the rest uniformly", () => {
        const bundle = bundleWith([
            { id: 1, notAfterMs: FAR },
            { id: 2, notAfterMs: FAR },
            { id: 3, notAfterMs: NOW_MS + 5001 },
            { id: 4, notAfterMs: NOW_MS + 5000 },
            { id: 5, notAfterMs: FAR },
            { id: 6, notAfterMs: FAR },
            { id: 7, notAfterMs: FAR },
            { id: 8, notAfterMs: FAR },
        ]);
        const used = new Set([2, 7]);
        const eligible = [1, 3, 5, 6, 8];
        const crypto = { randomBytes: vi.fn(seededRandomBytes(0x5eed)) };
        const counts = new Map<number, number>();
        const draws = 10_000;
        for (let i = 0; i < draws; i++) {
            const key = selectPreKey(bundle, used, NOW_MS, crypto);
            expect(key).toBeDefined();
            if (key === undefined) return;
            expect(bundle.prekeys).toContain(key);
            counts.set(key.id, (counts.get(key.id) ?? 0) + 1);
        }
        expect([...counts.keys()].sort((a, b) => a - b)).toEqual(eligible);
        const expected = draws / eligible.length;
        const chi2 = eligible.reduce(
            (sum, id) => sum + ((counts.get(id) ?? 0) - expected) ** 2 / expected,
            0,
        );
        expect(chi2).toBeLessThan(18.467); // χ²(df = 4) critical value at p = 0.001
        expect(crypto.randomBytes.mock.calls.every(([n]) => n === 4)).toBe(true);
    });

    it("(10) rejects draws in the biased tail instead of reducing them modulo n", () => {
        const bundle = bundleWith([1, 2, 3, 4, 5].map((id) => ({ id, notAfterMs: FAR })));
        // n = 5: the unbiased range is [0, 4294967295); 0xffffffff % 5 = 0 would favour index 0.
        const crypto = { randomBytes: vi.fn(scriptedRandomBytes([0xffffffff, 0xfffffffe])) };
        const key = selectPreKey(bundle, new Set(), NOW_MS, crypto);
        expect(key).toBe(bundle.prekeys[0xfffffffe % 5]);
        expect(crypto.randomBytes).toHaveBeenCalledTimes(2);
    });

    it("(10) returns the branded entry itself", () => {
        const bundle = bundleWith([{ id: 1, notAfterMs: FAR }]);
        const crypto = { randomBytes: scriptedRandomBytes([0]) };
        expect(selectPreKey(bundle, new Set(), NOW_MS, crypto)).toBe(bundle.prekeys[0]);
    });

    it("(10) returns undefined when every key is used or inside the margin", () => {
        const bundle = bundleWith([
            { id: 1, notAfterMs: FAR },
            { id: 2, notAfterMs: NOW_MS + 5000 },
            { id: 3, notAfterMs: NOW_MS - 1 },
        ]);
        const crypto = { randomBytes: vi.fn(scriptedRandomBytes([0])) };
        expect(selectPreKey(bundle, new Set([1]), NOW_MS, crypto)).toBeUndefined();
        expect(crypto.randomBytes).not.toHaveBeenCalled();
    });

    it("reads the drawn bytes from a randomBytes view with a non-zero byteOffset", () => {
        const bundle = bundleWith([1, 2, 3, 4, 5].map((id) => ({ id, notAfterMs: FAR })));
        let calls = 0;
        const randomBytes = (length: number): Bytes => {
            if (++calls > 10) throw new Error("draw loop never accepted a value");
            const backing = new Uint8Array(16).fill(0xff); // a pooled buffer: 0xffffffff would be rejected
            backing.set([0, 0, 0, 3], 8);
            return backing.subarray(8, 8 + length);
        };
        expect(selectPreKey(bundle, new Set(), NOW_MS, { randomBytes })).toBe(bundle.prekeys[3]);
    });

    it("ignores used ids that are not in the bundle", () => {
        const bundle = bundleWith([{ id: 1, notAfterMs: FAR }]);
        const crypto = { randomBytes: scriptedRandomBytes([7]) };
        expect(selectPreKey(bundle, new Set([42]), NOW_MS, crypto)).toBe(bundle.prekeys[0]);
    });
});
