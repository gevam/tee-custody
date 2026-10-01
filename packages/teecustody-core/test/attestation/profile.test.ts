// T-10: parseTrustProfile (API.md §D, §E; spec §15.4, §10.2; ADR 0009 rule 9; D-016). Security path.
import { describe, expect, it } from "vitest";

import { parseTrustProfile } from "../../src/attestation/profile.js";
import { isBrandedTrustProfile } from "../../src/attestation/types.js";

type ProfileJson = Record<string, unknown>;

const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const KEY_A = "0a".repeat(32);
const KEY_B = "0b".repeat(32);
const KEY_C = "0c".repeat(32);

function developmentJson(): ProfileJson {
    return {
        profile_version: 1,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration",
        jwks_origin: "http://127.0.0.1:8791",
        expected_audience: "https://unit.test/tee",
        token_max_age_s: 3600,
        allowed_hwmodels: ["UNIT_HW"],
        allowed_digests: [`sha256:${"ab".repeat(32)}`],
        signer_keys: [
            { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
            { key_id: KEY_B, algorithm: "RSASSA_PKCS1V15_SHA256" },
            { key_id: KEY_C, algorithm: "ECDSA_P256_SHA256" },
        ],
        signers_required: 2,
        expected_args_hash: "03".repeat(32),
        expected_env_hash: "04".repeat(32),
    };
}

function productionJson(): ProfileJson {
    return {
        ...developmentJson(),
        profile_kind: "production",
        issuer: GOOGLE_ISSUER,
        discovery_url: `${GOOGLE_ISSUER}/.well-known/openid-configuration`,
        jwks_origin: "https://www.googleapis.com",
        allowed_hwmodels: ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"],
    };
}

describe("parseTrustProfile accepts valid profiles", () => {
    it.each([
        ["development", developmentJson],
        ["production", productionJson],
    ])("returns a frozen, branded %s profile equal to its input", (_kind, build) => {
        const json = build();
        const profile = parseTrustProfile(json);

        expect(isBrandedTrustProfile(profile)).toBe(true);
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.allowed_hwmodels)).toBe(true);
        expect(Object.isFrozen(profile.allowed_digests)).toBe(true);
        expect(Object.isFrozen(profile.signer_keys)).toBe(true);
        expect(profile.signer_keys.every((key) => Object.isFrozen(key))).toBe(true);
        expect({ ...profile }).toEqual(json);
        expect(profile.signer_keys.map((key) => key.algorithm)).toEqual([
            "RSASSA_PSS_SHA256",
            "RSASSA_PKCS1V15_SHA256",
            "ECDSA_P256_SHA256",
        ]);
    });

    it("does not alias or freeze the caller's input", () => {
        const json = developmentJson();
        const profile = parseTrustProfile(json);

        expect(Object.isFrozen(json)).toBe(false);
        expect(profile.signer_keys).not.toBe(json.signer_keys);
        expect(profile.allowed_hwmodels).not.toBe(json.allowed_hwmodels);
        (json.allowed_hwmodels as string[]).push("LATER");
        expect(profile.allowed_hwmodels).toEqual(["UNIT_HW"]);
    });
});
