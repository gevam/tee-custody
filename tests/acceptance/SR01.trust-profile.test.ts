// SR-1 / FR-2 trust profile parsing: strictness at the configuration boundary (SR-3).
// Expected failure on trunk: NOT_IMPLEMENTED: T-10.
import { TrustProfileError, parseTrustProfile } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { ARGS_HASH, ENV_HASH, IMAGE_DIGEST, ISSUER } from "../support/token-factory.js";

const KEY_A = "a1".repeat(32);
const KEY_B = "b2".repeat(32);

const dev = (): Record<string, unknown> => ({
    profile_version: 1,
    profile_kind: "development",
    token_type: "OIDC",
    issuer: ISSUER,
    discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration",
    jwks_origin: "http://127.0.0.1:8791",
    expected_audience: "https://acceptance.teecustody.test/tee",
    token_max_age_s: 3600,
    allowed_hwmodels: ["SIMULATED"],
    allowed_digests: [IMAGE_DIGEST],
    signer_keys: [
        { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
        { key_id: KEY_B, algorithm: "RSASSA_PSS_SHA256" },
    ],
    signers_required: 2,
    expected_args_hash: ARGS_HASH,
    expected_env_hash: ENV_HASH,
});

function rejected(input: unknown): TrustProfileError {
    try {
        parseTrustProfile(input);
    } catch (error) {
        expect(error).toBeInstanceOf(TrustProfileError);
        return error as TrustProfileError;
    }
    throw new Error("parseTrustProfile accepted invalid input");
}

describe("FR-2 given a well-formed development profile", () => {
    it("parses and exposes the pinned values", () => {
        const profile = parseTrustProfile(dev());
        expect(profile.issuer).toBe(ISSUER);
        expect(profile.signers_required).toBe(2);
        expect(profile.signer_keys.map((k) => k.key_id)).toEqual([KEY_A, KEY_B]);
        expect(Object.isFrozen(profile)).toBe(true);
    });
});

describe("SR-1 (i) given a malformed signer entry", () => {
    const withSigners = (signer_keys: unknown) => ({ ...dev(), signer_keys });
    it.each([
        ["extra member", [{ key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256", spki: "AA" }]],
        ["missing algorithm", [{ key_id: KEY_A }]],
        ["uppercase key_id", [{ key_id: KEY_A.toUpperCase(), algorithm: "RSASSA_PSS_SHA256" }]],
        ["63 char key_id", [{ key_id: KEY_A.slice(0, 63), algorithm: "RSASSA_PSS_SHA256" }]],
        ["65 char key_id", [{ key_id: `${KEY_A}0`, algorithm: "RSASSA_PSS_SHA256" }]],
        ["sha256: key_id", [{ key_id: `sha256:${KEY_A}`, algorithm: "RSASSA_PSS_SHA256" }]],
        [
            "duplicate key_id",
            [
                { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
                { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
            ],
        ],
        ["algorithm outside set", [{ key_id: KEY_A, algorithm: "HMAC_SHA256" }]],
        ["not an array", { key_id: KEY_A }],
    ])("rejects %s", (_n, signers) => {
        expect(rejected(withSigners(signers)).code).toBe("INVALID_PROFILE");
    });
});

describe("SR-3 given structurally invalid profiles", () => {
    it.each([
        ["unknown top-level key", { ...dev(), skip_verification: true }],
        ["wrong profile_version", { ...dev(), profile_version: 2 }],
        ["unknown profile_kind", { ...dev(), profile_kind: "staging" }],
        ["signers_required zero", { ...dev(), signers_required: 0 }],
        ["signers_required above signer count", { ...dev(), signers_required: 3 }],
        ["non-hex args hash", { ...dev(), expected_args_hash: "xyz" }],
        ["empty digest list", { ...dev(), allowed_digests: [] }],
        ["bad digest form", { ...dev(), allowed_digests: ["sha256:ABC"] }],
        ["negative max age", { ...dev(), token_max_age_s: -1 }],
        ["non-object", "profile"],
        ["null", null],
    ])("rejects %s", (_n, input) => {
        expect(rejected(input).code).toMatch(/^(INVALID_PROFILE|UNSUPPORTED_TOKEN_TYPE)$/);
    });

    it("rejects an unsupported token type with its own code", () => {
        expect(rejected({ ...dev(), token_type: "PKI" }).code).toBe("UNSUPPORTED_TOKEN_TYPE");
    });

    it("error message is exactly 'field: CODE' and echoes no input value", () => {
        const err = rejected({
            ...dev(),
            expected_audience: 42,
            issuer: "https://leak-sentinel.test",
        });
        expect(err.message).toBe(`${err.field}: ${err.code}`);
        expect(err.message).not.toContain("leak-sentinel");
    });
});

describe("SR-1 given URL rules per profile kind", () => {
    it("rejects http discovery/JWKS URLs in a production profile", () => {
        const prod = {
            ...dev(),
            profile_kind: "production",
            issuer: "https://prod.example.test",
            allowed_hwmodels: ["GCP_INTEL_TDX"],
        };
        expect(rejected(prod).code).toBe("INVALID_PROFILE");
    });

    it.each([
        [
            "discovery_url",
            { discovery_url: "http://tee.example.test/.well-known/openid-configuration" },
        ],
        ["jwks_origin", { jwks_origin: "http://tee.example.test" }],
        [
            "both on a LAN address",
            { discovery_url: "http://192.168.1.5/x", jwks_origin: "http://192.168.1.5" },
        ],
    ])("rejects non-loopback http %s in a development profile", (_n, override) => {
        expect(rejected({ ...dev(), ...override }).code).toBe("INVALID_PROFILE");
    });
});
