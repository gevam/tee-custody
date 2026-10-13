// createWebCrypto (INC-2-API §8.1; T-17 criteria 1–3, 6; ADR 0011).
import { CapabilityError } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { createWebCrypto } from "../../src/crypto/webcrypto.js";

function codeOfThrown(fn: () => unknown): string {
    try {
        fn();
    } catch (error: unknown) {
        return error instanceof CapabilityError ? error.code : `not a CapabilityError: ${String(error)}`;
    }
    return "no error";
}

describe("randomBytes (criterion 1)", () => {
    it("rejects lengths outside 1..65536 with INVALID_ARGUMENT", () => {
        const crypto = createWebCrypto();
        expect(codeOfThrown(() => crypto.randomBytes(0))).toBe("INVALID_ARGUMENT");
        expect(codeOfThrown(() => crypto.randomBytes(65537))).toBe("INVALID_ARGUMENT");
    });

    it("returns n fresh random bytes on each call", () => {
        const crypto = createWebCrypto();
        const a = crypto.randomBytes(32);
        const b = crypto.randomBytes(32);
        expect(a).toHaveLength(32);
        expect(b).toHaveLength(32);
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });
});
