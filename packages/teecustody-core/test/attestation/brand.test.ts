// Runtime brand for VerifiedAttestation (INC-2-API §7.1; B-13; SR-1).
import { describe, expect, it } from "vitest";

import {
    createVerifiedAttestation,
    isVerifiedAttestation,
} from "../../src/attestation/types.js";

function fields() {
    return {
        issuer: "https://issuer.unit.test",
        audience: "https://unit.test/tee",
        imageDigest: `sha256:${"ab".repeat(32)}`,
        signerKeyIds: ["01".repeat(32)],
        hwmodel: "UNIT_HW",
        issuedAtMs: 1_000,
        expiresAtMs: 2_000,
    };
}

describe("isVerifiedAttestation", () => {
    it("is true for the value createVerifiedAttestation returned", () => {
        expect(isVerifiedAttestation(createVerifiedAttestation(fields()))).toBe(true);
    });

    it("is false for a structural copy, a frozen copy and non-objects", () => {
        const verified = createVerifiedAttestation(fields());
        expect(isVerifiedAttestation({ ...verified })).toBe(false);
        expect(isVerifiedAttestation(Object.freeze({ ...verified }))).toBe(false);
        expect(isVerifiedAttestation(fields())).toBe(false);
        expect(isVerifiedAttestation(null)).toBe(false);
        expect(isVerifiedAttestation(undefined)).toBe(false);
        expect(isVerifiedAttestation("attestation")).toBe(false);
    });
});
