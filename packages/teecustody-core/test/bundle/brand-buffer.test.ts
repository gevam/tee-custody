// T-16 A3 criterion 13: createVerifiedBundle copies Node Buffer inputs (Buffer#slice is a view, not a copy).
import { Buffer } from "node:buffer";

import { describe, expect, it, vi } from "vitest";

import { createVerifiedBundle } from "../../src/bundle/types.js";
import { NOW_MS, attestation } from "./support.js";

vi.mock("../../src/attestation/verify.js", () => ({ verifyAttestation: vi.fn() }));

describe("createVerifiedBundle with Buffer inputs (A3)", () => {
    it("(13) later mutation of the input Buffers does not reach the getters, which return plain copies", () => {
        const ikInput = Buffer.from(new Uint8Array(32).fill(7));
        const pubInput = Buffer.from(new Uint8Array(32).fill(1));
        const bundle = createVerifiedBundle({
            instanceId: "b2".repeat(16),
            identityPublicKey: ikInput,
            attestation: attestation(),
            prekeys: [{ id: 1, publicKey: pubInput, notAfterMs: NOW_MS + 60_000 }],
            verifiedAtMs: NOW_MS,
        });
        ikInput.fill(0xee);
        pubInput.fill(0xee);
        const reads: [Uint8Array, Buffer, number][] = [
            [bundle.identityPublicKey, ikInput, 7],
            [bundle.prekeys[0]?.publicKey ?? new Uint8Array(), pubInput, 1],
        ];
        for (const [read, input, fill] of reads) {
            expect(read).toEqual(new Uint8Array(32).fill(fill));
            expect(Buffer.isBuffer(read)).toBe(false);
            expect(Object.getPrototypeOf(read)).toBe(Uint8Array.prototype);
            expect(read.buffer).not.toBe(input.buffer);
        }
    });
});
