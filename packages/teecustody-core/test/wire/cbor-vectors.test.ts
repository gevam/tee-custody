// T-09 criteria 1-2: the shared canonical-CBOR conformance vectors (spec/vectors/wire/canonical-cbor.json).
import { readFileSync } from "node:fs";

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
    readonly invalid: readonly {
        readonly id: string;
        readonly hex: string;
        readonly error: string;
    }[];
}

const VECTORS_URL = new URL("../../../../spec/vectors/wire/canonical-cbor.json", import.meta.url);
const vectors = JSON.parse(readFileSync(VECTORS_URL, "utf8")) as CodecVectors;
const limits: DecodeLimits = {
    maxBytes: vectors.limits.max_bytes,
    maxDepth: vectors.limits.max_depth,
    maxItems: vectors.limits.max_items,
};

function fromHex(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex, "hex"));
}

function toHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

function validHex(id: string): string {
    const vector = vectors.valid.find((entry) => entry.id === id);
    if (vector === undefined) {
        throw new Error(`missing vector ${id}`);
    }
    return vector.hex;
}

describe("canonical-cbor.json valid cases (criterion 1)", () => {
    it.each(vectors.valid)("$id decodes and re-encodes to identical bytes", ({ hex }) => {
        expect(toHex(encodeCanonical(decodeCanonical(fromHex(hex), limits)))).toBe(hex);
    });

    it("maps the integer extremes to the documented JavaScript types", () => {
        expect(decodeCanonical(fromHex(validHex("uint_max")), limits)).toBe(18446744073709551615n);
        expect(decodeCanonical(fromHex(validHex("nint_min")), limits)).toBe(-18446744073709551616n);
        expect(decodeCanonical(fromHex(validHex("uint_1000000")), limits)).toBe(1000000);
    });
});

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

describe("canonical-cbor.json invalid cases (criterion 2, SR-3, SR-11)", () => {
    it.each(vectors.invalid)("$id is rejected with $error", ({ hex, error }) => {
        expect(wireErrorCode(() => decodeCanonical(fromHex(hex), limits))).toBe(error);
    });
});
