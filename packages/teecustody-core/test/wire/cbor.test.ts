// T-09 unit criteria for the canonical CBOR codec (spec/wire/README.md rules 1-5, SR-3, SR-11).
import { describe, expect, it } from "vitest";

import { decodeCanonical, encodeCanonical } from "../../src/wire/cbor.js";
import { WireError, type CanonicalValue, type DecodeLimits } from "../../src/wire/types.js";

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

// Values a caller can only produce by bypassing the type system.
function outsideModel(value: unknown): CanonicalValue {
    return value as CanonicalValue;
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

    it.each([
        ["1.5", 1.5],
        ["-0", -0],
        ["NaN", Number.NaN],
        ["2n ** 64n", 2n ** 64n],
        ["{a: 1}", outsideModel({ a: 1 })],
        ["undefined", outsideModel(undefined)],
        ["Map with a non-string key", outsideModel(new Map([[1, 2]]))],
        ["Uint16Array", outsideModel(new Uint16Array(1))],
    ])("refuses %s with UNSUPPORTED_TYPE (criterion 4)", (_name, value) => {
        expect(wireErrorCode(() => encodeCanonical(value))).toBe("UNSUPPORTED_TYPE");
    });

    it("encodes true as f5 (criterion 4)", () => {
        expect(toHex(encodeCanonical(true))).toBe("f5");
    });
});

describe("decodeCanonical bounds", () => {
    it("rejects 10,000 nested arrays at maxDepth 16 without exhausting the call stack (criterion 5)", () => {
        const limits: DecodeLimits = { maxBytes: 20_000, maxDepth: 16, maxItems: 20_000 };
        const input = fromHex("81".repeat(10_000) + "00");
        expect(wireErrorCode(() => decodeCanonical(input, limits))).toBe("LIMIT_EXCEEDED");
    });

    it("decodes and re-encodes 100,000 nested arrays when the limits allow it (no recursion)", () => {
        const limits: DecodeLimits = { maxBytes: 200_000, maxDepth: 200_000, maxItems: 200_000 };
        const hex = "81".repeat(100_000) + "00";
        expect(toHex(encodeCanonical(decodeCanonical(fromHex(hex), limits)))).toBe(hex);
    });
});
