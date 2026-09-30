// Contract: normative canonical-CBOR binding, TypeScript side (API.md §D wire; spec/wire/README.md).
// Expected red until T-03 (vectors) and T-09 (codec) merge; the corpus test until T-18.
import { describe, expect, it } from "vitest";

import {
    PROTO,
    WireError,
    decodeCanonical,
    encodeCanonical,
    type CanonicalValue,
} from "@teecustody/core";

import { readRepoFile } from "../../support/repo.js";

interface CodecVectors {
    readonly limits: {
        readonly max_bytes: number;
        readonly max_depth: number;
        readonly max_items: number;
    };
    readonly valid: readonly { readonly id: string; readonly hex: string }[];
    readonly invalid: readonly {
        readonly id: string;
        readonly hex: string;
        readonly error: string;
    }[];
}

interface DifferentialCorpus {
    readonly limits: {
        readonly max_bytes: number;
        readonly max_depth: number;
        readonly max_items: number;
    };
    readonly cases: readonly {
        readonly id: string;
        readonly hex: string;
        readonly outcome: string;
    }[];
}

function loadVectors(): CodecVectors {
    const text = new TextDecoder().decode(readRepoFile("spec/vectors/wire/canonical-cbor.json"));
    return JSON.parse(text) as CodecVectors;
}

function fromHex(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex, "hex"));
}

function toHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

function wireErrorCode(action: () => unknown): string {
    try {
        action();
    } catch (error) {
        if (error instanceof WireError) {
            expect(error.message).toBe(error.code);
            return error.code;
        }
        throw error;
    }
    return "NO_ERROR";
}

describe("canonical CBOR binding", () => {
    it("binds the normative protocol identifier", () => {
        expect(PROTO).toBe("tee-chan-v1");
    });

    it("orders map keys by their encoded bytes", () => {
        const value: CanonicalValue = new Map<string, CanonicalValue>([
            ["b", 1],
            ["aa", 2],
        ]);
        expect(toHex(encodeCanonical(value))).toBe("a261620162616102");
    });

    it("maps CBOR types to the documented JavaScript types", () => {
        const limits = { maxBytes: 64, maxDepth: 4, maxItems: 16 };
        expect(decodeCanonical(fromHex("1bffffffffffffffff"), limits)).toBe(18446744073709551615n);
        expect(decodeCanonical(fromHex("1a000f4240"), limits)).toBe(1000000);
        expect(decodeCanonical(fromHex("1b001fffffffffffff"), limits)).toBe(9007199254740991);
        expect(decodeCanonical(fromHex("1b0020000000000000"), limits)).toBe(9007199254740992n);
        expect(decodeCanonical(fromHex("a0"), limits)).toBeInstanceOf(Map);
        expect(decodeCanonical(fromHex("4401020304"), limits)).toEqual(
            new Uint8Array([1, 2, 3, 4]),
        );
    });

    it("round-trips every valid shared vector byte for byte", () => {
        const vectors = loadVectors();
        const limits = {
            maxBytes: vectors.limits.max_bytes,
            maxDepth: vectors.limits.max_depth,
            maxItems: vectors.limits.max_items,
        };
        for (const vector of vectors.valid) {
            const bytes = fromHex(vector.hex);
            expect(toHex(encodeCanonical(decodeCanonical(bytes, limits))), vector.id).toBe(
                vector.hex,
            );
        }
    });

    it("rejects every invalid shared vector with its stable code", () => {
        const vectors = loadVectors();
        const limits = {
            maxBytes: vectors.limits.max_bytes,
            maxDepth: vectors.limits.max_depth,
            maxItems: vectors.limits.max_items,
        };
        for (const vector of vectors.invalid) {
            const code = wireErrorCode(() => decodeCanonical(fromHex(vector.hex), limits));
            expect(code, vector.id).toBe(vector.error);
        }
    });

    it("refuses values outside the data model when encoding", () => {
        expect(wireErrorCode(() => encodeCanonical(1.5))).toBe("UNSUPPORTED_TYPE");
        expect(wireErrorCode(() => encodeCanonical(2n ** 64n))).toBe("UNSUPPORTED_TYPE");
    });

    it("agrees with the Python codec on every differential-corpus case (ADR 0010)", () => {
        const corpus = JSON.parse(
            new TextDecoder().decode(readRepoFile("spec/vectors/wire/differential-corpus.json")),
        ) as DifferentialCorpus;
        expect(corpus.cases.length).toBeGreaterThanOrEqual(500);
        const limits = {
            maxBytes: corpus.limits.max_bytes,
            maxDepth: corpus.limits.max_depth,
            maxItems: corpus.limits.max_items,
        };
        for (const entry of corpus.cases) {
            const outcome = wireErrorCode(() => decodeCanonical(fromHex(entry.hex), limits));
            expect(outcome === "NO_ERROR" ? "accept" : outcome, entry.id).toBe(entry.outcome);
        }
    });
});
