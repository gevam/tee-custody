import { describe, expect, it } from "vitest";

import {
    AttestationError,
    TrustProfileError,
    brandTrustProfile,
    createVerifiedAttestation,
    isBrandedTrustProfile,
} from "../../src/attestation/types.js";

type ProfileFields = Parameters<typeof brandTrustProfile>[0];

function profileFields(): ProfileFields {
    return {
        profile_version: 2,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        jwks_uri: "http://127.0.0.1:1/jwks",
        expected_audience: "https://unit.test/tee",
        token_max_age_s: 3600,
        allowed_hwmodels: ["UNIT_HW"],
        allowed_digests: [`sha256:${"ab".repeat(32)}`],
        signer_keys: [
            { key_id: "01".repeat(32), algorithm: "RSASSA_PSS_SHA256" },
            { key_id: "02".repeat(32), algorithm: "ECDSA_P256_SHA256" },
        ],
        signers_required: 2,
        expected_args_hash: "03".repeat(32),
        expected_env_hash: "04".repeat(32),
    };
}

describe("AttestationError", () => {
    it("has message `${check}: ${code}` and exposes code and check", () => {
        const error = new AttestationError("EXPIRED", "time");
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe("time: EXPIRED");
        expect(error.code).toBe("EXPIRED");
        expect(error.check).toBe("time");
    });
});

describe("TrustProfileError", () => {
    it("has message `${field}: ${code}` and exposes code and field", () => {
        const error = new TrustProfileError("INVALID_PROFILE", "signer_keys[0].key_id");
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe("signer_keys[0].key_id: INVALID_PROFILE");
        expect(error.code).toBe("INVALID_PROFILE");
        expect(error.field).toBe("signer_keys[0].key_id");
    });
});

describe("brandTrustProfile / isBrandedTrustProfile", () => {
    it("deep-freezes the profile and brands it", () => {
        const profile = brandTrustProfile(profileFields());
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.allowed_hwmodels)).toBe(true);
        expect(Object.isFrozen(profile.allowed_digests)).toBe(true);
        expect(Object.isFrozen(profile.signer_keys)).toBe(true);
        for (const signer of profile.signer_keys) {
            expect(Object.isFrozen(signer)).toBe(true);
        }
        expect(isBrandedTrustProfile(profile)).toBe(true);
    });

    it("does not brand a structurally identical plain object", () => {
        brandTrustProfile(profileFields());
        expect(isBrandedTrustProfile(profileFields())).toBe(false);
        expect(isBrandedTrustProfile(Object.freeze(profileFields()))).toBe(false);
    });

    it("rejects non-objects", () => {
        expect(isBrandedTrustProfile(null)).toBe(false);
        expect(isBrandedTrustProfile(undefined)).toBe(false);
        expect(isBrandedTrustProfile("profile")).toBe(false);
    });
});

describe("createVerifiedAttestation", () => {
    it("returns a frozen object, including its signer list, detached from the input", () => {
        const signerKeyIds = ["01".repeat(32), "02".repeat(32)];
        const fields = {
            issuer: "https://issuer.unit.test",
            audience: "https://unit.test/tee",
            imageDigest: `sha256:${"ab".repeat(32)}`,
            signerKeyIds,
            hwmodel: "UNIT_HW",
            issuedAtMs: 1_000,
            expiresAtMs: 2_000,
        };
        const verified = createVerifiedAttestation(fields);
        expect(Object.isFrozen(verified)).toBe(true);
        expect(Object.isFrozen(verified.signerKeyIds)).toBe(true);
        expect(verified).toEqual(fields);
        signerKeyIds.push("03".repeat(32));
        expect(verified.signerKeyIds).toHaveLength(2);
    });
});
