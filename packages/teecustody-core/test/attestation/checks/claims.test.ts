import { describe, expect, it } from "vitest";

import { checkAudience, checkTime } from "../../../src/attestation/checks/claims.js";
import {
    AttestationError,
    brandTrustProfile,
    type AttestationCheckId,
    type AttestationErrorCode,
    type ParsedToken,
    type TrustProfile,
} from "../../../src/attestation/types.js";
import type { JsonObject, JsonValue } from "../../../src/json.js";

const AUDIENCE = "https://unit.test/tee";
const NOW_S = 1_800_000_000;
const NOW_MS = NOW_S * 1000;
const MAX_AGE_S = 3600;

const PROFILE: TrustProfile = brandTrustProfile({
    profile_version: 1,
    profile_kind: "development",
    token_type: "OIDC",
    issuer: "https://issuer.unit.test",
    discovery_url: "http://127.0.0.1:1/.well-known/openid-configuration",
    jwks_origin: "http://127.0.0.1:1",
    expected_audience: AUDIENCE,
    token_max_age_s: MAX_AGE_S,
    allowed_hwmodels: ["GCP_AMD_SEV", "GCP_INTEL_TDX"],
    allowed_digests: [`sha256:${"ab".repeat(32)}`],
    signer_keys: [{ key_id: "01".repeat(32), algorithm: "RSASSA_PSS_SHA256" }],
    signers_required: 1,
    expected_args_hash: "03".repeat(32),
    expected_env_hash: "04".repeat(32),
});

function token(claims: JsonObject): ParsedToken {
    return {
        header: { alg: "RS256", kid: "unit" },
        claims,
        signingInput: new Uint8Array([1]),
        signature: new Uint8Array([2]),
    };
}

function failure(run: () => void): AttestationError {
    try {
        run();
    } catch (error) {
        expect(error).toBeInstanceOf(AttestationError);
        return error as AttestationError;
    }
    throw new Error("expected the check to throw");
}

function expectRejected(
    run: () => void,
    check: AttestationCheckId,
    code: AttestationErrorCode,
): void {
    const error = failure(run);
    expect([error.check, error.code]).toEqual([check, code]);
}

const audience = (claims: JsonObject) => (): void => {
    checkAudience(token(claims), PROFILE);
};

describe("checkAudience (§6.3)", () => {
    it("passes on the expected audience", () => {
        expect(audience({ aud: AUDIENCE })).not.toThrow();
    });

    it("rejects an absent aud with CLAIM_MISSING", () => {
        expectRejected(audience({}), "audience", "CLAIM_MISSING");
    });

    it.each<[string, JsonObject]>([
        ["a different string", { aud: "https://other.test/tee" }],
        ["an array", { aud: [AUDIENCE] }],
        ["an array of another value", { aud: ["x"] }],
    ])("rejects %s with CLAIM_MISMATCH", (_label, claims) => {
        expectRejected(audience(claims), "audience", "CLAIM_MISMATCH");
    });
});

const time = (claims: JsonObject) => (): void => {
    checkTime(token(claims), PROFILE, NOW_MS);
};

const FRESH: JsonObject = { exp: NOW_S + 1, iat: NOW_S };

describe("checkTime (§6.4)", () => {
    it.each<[string, JsonObject]>([
        ["exp one second in the future", FRESH],
        ["iat exactly max age in the past", { ...FRESH, iat: NOW_S - MAX_AGE_S }],
        ["iat exactly max age in the future", { ...FRESH, iat: NOW_S + MAX_AGE_S }],
        ["nbf equal to now", { ...FRESH, nbf: NOW_S }],
        ["nbf in the past", { ...FRESH, nbf: NOW_S - 10 }],
    ])("passes with %s", (_label, claims) => {
        expect(time(claims)).not.toThrow();
    });

    it.each<[string, JsonObject, AttestationErrorCode]>([
        ["exp equal to now (no leeway)", { ...FRESH, exp: NOW_S }, "EXPIRED"],
        ["exp in the past", { ...FRESH, exp: NOW_S - 60 }, "EXPIRED"],
        ["iat one second older than max age", { ...FRESH, iat: NOW_S - MAX_AGE_S - 1 }, "EXPIRED"],
        [
            "iat one second further ahead than max age",
            { ...FRESH, iat: NOW_S + MAX_AGE_S + 1 },
            "NOT_YET_VALID",
        ],
        ["nbf one second ahead (no skew)", { ...FRESH, nbf: NOW_S + 1 }, "NOT_YET_VALID"],
        ["absent exp", { iat: NOW_S }, "CLAIM_MISSING"],
        ["absent iat", { exp: NOW_S + 1 }, "CLAIM_MISSING"],
    ])("rejects %s", (_label, claims, code) => {
        expectRejected(time(claims), "time", code);
    });

    it.each<[string, JsonObject]>(
        [
            ["a numeric string", "1"],
            ["a fraction", 1.5],
            ["a negative integer", -1],
            ["a boolean", true],
            ["null", null],
            ["an unsafe integer", 2 ** 53],
            ["an array", [NOW_S + 1]],
        ].flatMap(([label, value]) => [
            [`exp as ${String(label)}`, { ...FRESH, exp: value as JsonValue }],
            [`iat as ${String(label)}`, { ...FRESH, iat: value as JsonValue }],
            [`nbf as ${String(label)}`, { ...FRESH, nbf: value as JsonValue }],
        ]),
    )("rejects %s with CLAIM_MISMATCH", (_label, claims) => {
        expectRejected(time(claims), "time", "CLAIM_MISMATCH");
    });

    it("checks exp before iat", () => {
        expectRejected(time({ exp: "1" }), "time", "CLAIM_MISMATCH");
        expectRejected(time({ exp: NOW_S, iat: "1" }), "time", "EXPIRED");
    });

    it("checks iat before nbf", () => {
        expectRejected(time({ ...FRESH, iat: true, nbf: NOW_S + 1 }), "time", "CLAIM_MISMATCH");
    });
});
