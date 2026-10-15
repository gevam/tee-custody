// SR-1 / FR-2 trust profile parsing: strictness at the configuration boundary (SR-3).
// Expected failure on trunk: NOT_IMPLEMENTED: T-10.
import { TrustProfileError, parseTrustProfile } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { ARGS_HASH, ENV_HASH, IMAGE_DIGEST, ISSUER } from "../support/token-factory.js";

const KEY_A = "a1".repeat(32);
const KEY_B = "b2".repeat(32);

const dev = (): Record<string, unknown> => ({
    profile_version: 2,
    profile_kind: "development",
    token_type: "OIDC",
    issuer: ISSUER,
    jwks_uri: "http://127.0.0.1:8791/jwks",
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

const without = (o: Record<string, unknown>, key: string): Record<string, unknown> =>
    Object.fromEntries(Object.entries(o).filter(([k]) => k !== key));

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
        ["not an array", { key_id: KEY_A }],
    ])("rejects %s", (_n, signers) => {
        expect(rejected(withSigners(signers)).code).toBe("INVALID_PROFILE");
    });
});

describe("SR-1 (i) given a signer algorithm outside the allowed set", () => {
    it("rejects with UNSUPPORTED_ALGORITHM (API.md TrustProfileErrorCode)", () => {
        const input = {
            ...dev(),
            signer_keys: [{ key_id: KEY_A, algorithm: "HMAC_SHA256" }],
            signers_required: 1,
        };
        expect(rejected(input).code).toBe("UNSUPPORTED_ALGORITHM");
    });
});

describe("SR-3 given structurally invalid profiles", () => {
    it.each([
        ["unknown top-level key", { ...dev(), skip_verification: true }],
        ["wrong profile_version", { ...dev(), profile_version: 3 }],
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

const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
const prod = (): Record<string, unknown> => ({
    ...dev(),
    profile_kind: "production",
    issuer: GOOGLE_ISSUER,
    jwks_uri: GOOGLE_JWKS_URI,
    allowed_hwmodels: ["GCP_INTEL_TDX"],
});

describe("SR-1 / D-043 given a v1 profile or retired discovery fields", () => {
    it("rejects the INC-1 v1 shape at profile_version, before any key-set check", () => {
        const rest = without(dev(), "jwks_uri");
        const v1 = {
            ...rest,
            profile_version: 1,
            discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration",
            jwks_origin: "http://127.0.0.1:8791",
        };
        const err = rejected(v1);
        expect([err.code, err.field]).toEqual(["INVALID_PROFILE", "profile_version"]);
    });

    it.each([
        ["discovery_url", "http://127.0.0.1:8791/.well-known/openid-configuration"],
        ["jwks_origin", "http://127.0.0.1:8791"],
    ])("rejects a v2 profile that still carries %s", (field, value) => {
        const err = rejected({ ...dev(), [field]: value });
        expect([err.code, err.field]).toEqual(["INVALID_PROFILE", field]);
    });

    it("rejects a v2 profile without jwks_uri", () => {
        const rest = without(dev(), "jwks_uri");
        const err = rejected(rest);
        expect([err.code, err.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });

    it("has exactly 13 keys", () => {
        expect(Object.keys(dev())).toHaveLength(13);
        expect(parseTrustProfile(dev()).jwks_uri).toBe("http://127.0.0.1:8791/jwks");
    });
});

describe("SR-1 / D-043 given URL rules per profile kind", () => {
    it("accepts the exact Google jwks_uri in a production profile", () => {
        expect(parseTrustProfile(prod()).jwks_uri).toBe(GOOGLE_JWKS_URI);
    });

    it.each([
        ["a trailing slash", `${GOOGLE_JWKS_URI}/`],
        ["an upper-case host", GOOGLE_JWKS_URI.replace("www.googleapis.com", "WWW.googleapis.com")],
        ["%40 in place of @", GOOGLE_JWKS_URI.replace("@", "%40")],
        ["a path variant", GOOGLE_JWKS_URI.replace("signer@", "other@")],
        ["a query", `${GOOGLE_JWKS_URI}?x=1`],
        ["a fragment", `${GOOGLE_JWKS_URI}#x`],
        ["an explicit port", GOOGLE_JWKS_URI.replace(".com/", ".com:443/")],
        ["plain http", GOOGLE_JWKS_URI.replace("https:", "http:")],
        ["a loopback address", "http://127.0.0.1:8791/jwks"],
        ["leading whitespace", ` ${GOOGLE_JWKS_URI}`],
        ["an empty string", ""],
    ])("rejects a production jwks_uri with %s, at jwks_uri", (_n, uri) => {
        const err = rejected({ ...prod(), jwks_uri: uri });
        expect([err.code, err.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });

    it.each([
        ["a non-loopback host", "http://tee.example.test/jwks"],
        ["a LAN address", "http://192.168.1.5:8791/jwks"],
        ["another path", "http://127.0.0.1:8791/attacker/jwks"],
        ["a trailing slash", "http://127.0.0.1:8791/jwks/"],
        ["an upper-case path", "http://127.0.0.1:8791/JWKS"],
        ["a query", "http://127.0.0.1:8791/jwks?x=1"],
        ["userinfo", "http://user@127.0.0.1:8791/jwks"],
    ])("rejects a development jwks_uri with %s, at jwks_uri", (_n, uri) => {
        const err = rejected({ ...dev(), jwks_uri: uri });
        expect([err.code, err.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });
});
