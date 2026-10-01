// T-09 unit criteria for the canonical CBOR codec (spec/wire/README.md rules 1-5, SR-3, SR-11).
import { describe, expect, it } from "vitest";

import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import { WireError, type CanonicalValue, type DecodeLimits } from "../../src/wire/types.js";

// The limits of spec/vectors/wire/canonical-cbor.json.
const VECTOR_LIMITS: DecodeLimits = { maxBytes: 1024, maxDepth: 4, maxItems: 64 };

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

describe("encodeCanonical", () => {
    it("orders map keys by their encoded bytes (criterion 3)", () => {
        const value: CanonicalValue = new Map<string, CanonicalValue>([
            ["b", 1],
            ["aa", 2],
        ]);
        expect(toHex(encodeCanonical(value))).toBe("a261620162616102");
        const reversed: CanonicalValue = new Map<string, CanonicalValue>([
            ["aa", 2],
            ["b", 1],
        ]);
        expect(toHex(encodeCanonical(reversed))).toBe("a261620162616102");
    });
});
