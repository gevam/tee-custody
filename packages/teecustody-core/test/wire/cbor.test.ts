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

    it("copies decoded byte strings out of the input buffer (criterion 6)", () => {
        const input = fromHex("4401020304");
        const decoded = decodeCanonical(input, VECTOR_LIMITS);
        input.fill(0xff);
        expect(decoded).toEqual(new Uint8Array([1, 2, 3, 4]));
    });
});

describe("decodeCanonical limits validation", () => {
    it.each([
        ["maxBytes 0", { maxBytes: 0, maxDepth: 1, maxItems: 1 }],
        ["maxDepth 1.5", { maxBytes: 1024, maxDepth: 1.5, maxItems: 64 }],
        ["maxBytes NaN", { maxBytes: Number.NaN, maxDepth: 4, maxItems: 64 }],
        ["maxDepth Infinity", { maxBytes: 1024, maxDepth: Infinity, maxItems: 64 }],
        ["maxItems -1", { maxBytes: 1024, maxDepth: 4, maxItems: -1 }],
        ["maxItems 2^53", { maxBytes: 1024, maxDepth: 4, maxItems: 2 ** 53 }],
    ])("throws RangeError(INVALID_LIMITS) for %s before parsing (criterion 9)", (_name, limits) => {
        expect(() => decodeCanonical(fromHex("00"), limits)).toThrow(
            new RangeError("INVALID_LIMITS"),
        );
    });
});

describe("allocation guard (criterion 10, ADR 0010)", () => {
    it.each([
        ["9b0000000100000000", "LIMIT_EXCEEDED"],
        ["bb8000000000000000", "LIMIT_EXCEEDED"],
        ["5bffffffffffffffff", "MALFORMED"],
    ])("rejects %s with %s without allocating for the declared size", (hex, code) => {
        const input = fromHex(hex);
        const before = process.memoryUsage().arrayBuffers;
        const outcome = wireErrorCode(() => decodeCanonical(input, VECTOR_LIMITS));
        const growth = process.memoryUsage().arrayBuffers - before;
        expect(outcome).toBe(code);
        expect(growth).toBeLessThan(64 * 1024);
    });

    it("rejects a byte string declaring more bytes than remain (590100)", () => {
        expect(wireErrorCode(() => decodeCanonical(fromHex("590100"), VECTOR_LIMITS))).toBe(
            "MALFORMED",
        );
    });
});

describe("integer boundaries (criterion 11, SR-3)", () => {
    it("decodes 2^53 - 1 as a number and 2^53, 2^53 + 1 as exact bigints", () => {
        expect(decodeCanonical(fromHex("1b001fffffffffffff"), VECTOR_LIMITS)).toBe(
            9007199254740991,
        );
        expect(decodeCanonical(fromHex("1b0020000000000000"), VECTOR_LIMITS)).toBe(
            9007199254740992n,
        );
        expect(decodeCanonical(fromHex("1b0020000000000001"), VECTOR_LIMITS)).toBe(
            9007199254740993n,
        );
    });

    it.each([9007199254740992n, 2n ** 53n - 1n])("encodes %s and round-trips it", (value) => {
        const encoded = encodeCanonical(value);
        expect(encodeCanonical(decodeCanonical(encoded, VECTOR_LIMITS))).toEqual(encoded);
        expect(BigInt(decodeCanonical(encoded, VECTOR_LIMITS) as number | bigint)).toBe(value);
    });
});

describe("prototype safety (criterion 13)", () => {
    it("decodes a __proto__ key into a Map entry and leaves Object.prototype alone", () => {
        const prototypeKeys = Object.getOwnPropertyNames(Object.prototype);
        const decoded = decodeCanonical(fromHex("a1695f5f70726f746f5f5f00"), VECTOR_LIMITS);
        expect(decoded).toBeInstanceOf(Map);
        const entries = decoded as ReadonlyMap<string, CanonicalValue>;
        expect([...entries.keys()]).toEqual(["__proto__"]);
        expect(entries.get("__proto__")).toBe(0);
        expect(Object.getOwnPropertyNames(Object.prototype)).toEqual(prototypeKeys);
        expect(Object.getPrototypeOf(entries)).toBe(Map.prototype);
        expect(toHex(encodeCanonical(decoded))).toBe("a1695f5f70726f746f5f5f00");
    });
});

describe("64-bit arguments (criterion 14, D-020)", () => {
    it.each([
        ["5b0000000100000000", "MALFORMED"],
        ["7b0000000100000000", "MALFORMED"],
        ["9b0000000100000000", "LIMIT_EXCEEDED"],
        ["bb0000000100000000", "LIMIT_EXCEEDED"],
    ])("reads the full 64-bit argument of %s (%s, not its low 32 bits)", (hex, code) => {
        expect(wireErrorCode(() => decodeCanonical(fromHex(hex), VECTOR_LIMITS))).toBe(code);
    });
});

describe("encodeCanonical edge cases", () => {
    it("encodes -2^64 and refuses -2^64 - 1", () => {
        expect(toHex(encodeCanonical(-(2n ** 64n)))).toBe("3bffffffffffffffff");
        expect(wireErrorCode(() => encodeCanonical(-(2n ** 64n) - 1n))).toBe("UNSUPPORTED_TYPE");
    });

    it("refuses undefined array elements and holes instead of writing null", () => {
        expect(wireErrorCode(() => encodeCanonical(outsideModel([undefined])))).toBe(
            "UNSUPPORTED_TYPE",
        );
        expect(wireErrorCode(() => encodeCanonical(outsideModel(new Array(2))))).toBe(
            "UNSUPPORTED_TYPE",
        );
    });

    it("refuses strings with lone surrogates instead of encoding them lossily", () => {
        expect(wireErrorCode(() => encodeCanonical("a\ud800"))).toBe("UNSUPPORTED_TYPE");
        expect(wireErrorCode(() => encodeCanonical(new Map([["\udc00", 1]])))).toBe(
            "UNSUPPORTED_TYPE",
        );
        expect(toHex(encodeCanonical("\ud83d\ude00"))).toBe("64f09f9880");
    });

    it("refuses cyclic containers and accepts shared acyclic ones", () => {
        const cyclicArray: unknown[] = [];
        cyclicArray.push(cyclicArray);
        expect(wireErrorCode(() => encodeCanonical(outsideModel(cyclicArray)))).toBe(
            "UNSUPPORTED_TYPE",
        );
        const cyclicMap = new Map<string, unknown>();
        cyclicMap.set("self", [cyclicMap]);
        expect(wireErrorCode(() => encodeCanonical(outsideModel(cyclicMap)))).toBe(
            "UNSUPPORTED_TYPE",
        );
        const shared: CanonicalValue = [1];
        expect(toHex(encodeCanonical([shared, shared]))).toBe("82810181" + "01");
    });
});
