import { describe, expect, it } from "vitest";

import {
    checkAudience,
    checkNonce,
    checkPlatform,
    checkSupportAttributes,
    checkTime,
    isDebugMode,
} from "../../../src/attestation/checks/claims.js";
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

const IDENTITY_NONCE = Uint8Array.from({ length: 32 }, (_, i) => (0xa0 + i * 7) % 256);
const EXPECTED_NONCE = Buffer.from(IDENTITY_NONCE).toString("hex");

const nonce =
    (claims: JsonObject, identityNonce: Uint8Array = IDENTITY_NONCE) =>
    (): void => {
        checkNonce(token(claims), { identityNonce });
    };

describe("checkNonce (§6.5)", () => {
    it.each<[string, JsonValue]>([
        ["the expected lowercase hex string", EXPECTED_NONCE],
        ["a one-element array holding it", [EXPECTED_NONCE]],
    ])("passes on %s", (_label, value) => {
        expect(nonce({ eat_nonce: value })).not.toThrow();
    });

    it("rejects an absent eat_nonce with CLAIM_MISSING", () => {
        expectRejected(nonce({}), "nonce", "CLAIM_MISSING");
    });

    it.each<[string, JsonValue]>([
        ["a two-element array", [EXPECTED_NONCE, EXPECTED_NONCE]],
        ["uppercase hex", EXPECTED_NONCE.toUpperCase()],
        ["a number", 42],
        ["an empty array", []],
        ["an array holding a number", [42]],
        ["a different nonce", "00".repeat(32)],
        ["an array holding a different nonce", ["00".repeat(32)]],
        ["an object", { nonce: EXPECTED_NONCE }],
        ["null", null],
    ])("rejects %s with CLAIM_MISMATCH", (_label, value) => {
        expectRejected(nonce({ eat_nonce: value }), "nonce", "CLAIM_MISMATCH");
    });

    it.each([31, 33, 0])("rejects a %i-byte identityNonce with MALFORMED", (length) => {
        const identityNonce = new Uint8Array(length);
        const expected = Buffer.from(identityNonce).toString("hex");
        expectRejected(nonce({ eat_nonce: expected }, identityNonce), "nonce", "MALFORMED");
    });

    it("checks the identityNonce length before the claim", () => {
        expectRejected(nonce({}, new Uint8Array(31)), "nonce", "MALFORMED");
    });
});

const PLATFORM: JsonObject = {
    hwmodel: "GCP_AMD_SEV",
    swname: "CONFIDENTIAL_SPACE",
    secboot: true,
    dbgstat: "disabled-since-boot",
};

const platform = (claims: JsonObject) => (): void => {
    checkPlatform(token(claims), PROFILE);
};

function without(claims: JsonObject, name: string): JsonObject {
    return Object.fromEntries(Object.entries(claims).filter(([key]) => key !== name));
}

describe("checkPlatform (§6.6)", () => {
    it.each(["GCP_AMD_SEV", "GCP_INTEL_TDX"])("passes with every field correct (%s)", (hwmodel) => {
        expect(platform({ ...PLATFORM, hwmodel })).not.toThrow();
    });

    it.each(["hwmodel", "swname", "secboot", "dbgstat"])(
        "rejects an absent %s with CLAIM_MISSING",
        (name) => {
            expectRejected(platform(without(PLATFORM, name)), "platform", "CLAIM_MISSING");
        },
    );

    it.each<[string, JsonObject]>([
        ["hwmodel not in allowed_hwmodels", { hwmodel: "GCP_ARM_CCA" }],
        ["hwmodel in another case", { hwmodel: "gcp_amd_sev" }],
        ["hwmodel as an array", { hwmodel: ["GCP_AMD_SEV"] }],
        ["hwmodel as a number", { hwmodel: 42 }],
        ["swname GCE (revoked image, F-15)", { swname: "GCE" }],
        ["swname in another case", { swname: "confidential_space" }],
        ["swname as an array", { swname: ["CONFIDENTIAL_SPACE"] }],
        ["secboot false", { secboot: false }],
        ["secboot as the string true", { secboot: "true" }],
        ["secboot as 1", { secboot: 1 }],
        ["dbgstat enabled", { dbgstat: "enabled" }],
        ["dbgstat empty", { dbgstat: "" }],
        ["dbgstat as a number", { dbgstat: 42 }],
        ["dbgstat null", { dbgstat: null }],
    ])("rejects %s with CLAIM_MISMATCH", (_label, change) => {
        expectRejected(platform({ ...PLATFORM, ...change }), "platform", "CLAIM_MISMATCH");
    });

    it("checks hwmodel, swname, secboot, dbgstat in that order", () => {
        const order = ["hwmodel", "swname", "secboot", "dbgstat"];
        const wrong: JsonObject = {
            hwmodel: "GCP_ARM_CCA",
            swname: "GCE",
            secboot: false,
            dbgstat: "enabled",
        };
        order.slice(0, -1).forEach((name, index) => {
            const next = order[index + 1] as string;
            const claims = without({ ...PLATFORM, [name]: wrong[name] as JsonValue }, next);
            expectRejected(platform(claims), "platform", "CLAIM_MISMATCH");
        });
    });
});

describe("isDebugMode (§6.6 / SR-12)", () => {
    it.each<[string, JsonObject, boolean]>([
        ["dbgstat enabled", { dbgstat: "enabled" }, true],
        ["dbgstat disabled-since-boot", { dbgstat: "disabled-since-boot" }, false],
        ["dbgstat absent", {}, false],
        ["dbgstat a number", { dbgstat: 42 }, true],
        ["dbgstat null", { dbgstat: null }, true],
        ["dbgstat in another case", { dbgstat: "DISABLED-SINCE-BOOT" }, true],
        ["dbgstat as a one-element array", { dbgstat: ["disabled-since-boot"] }, true],
    ])("given %s returns %s and never throws", (_label, claims, debug) => {
        expect(isDebugMode(token(claims))).toBe(debug);
    });
});

const supportAttributes = (claims: JsonObject) => (): void => {
    checkSupportAttributes(token(claims));
};

function withAttributes(value: JsonValue): JsonObject {
    return { submods: { confidential_space: { support_attributes: value } } };
}

describe("checkSupportAttributes (§6.7)", () => {
    it.each<[string, JsonValue]>([
        ["all documented production values", ["LATEST", "STABLE", "USABLE"]],
        ["STABLE alone", ["STABLE"]],
        ["USABLE and STABLE", ["USABLE", "STABLE"]],
    ])("passes on %s", (_label, value) => {
        expect(supportAttributes(withAttributes(value))).not.toThrow();
    });

    it.each<[string, JsonObject]>([
        ["absent submods", {}],
        ["absent confidential_space", { submods: { container: {} } }],
        ["absent support_attributes", { submods: { confidential_space: {} } }],
        ["submods not an object", { submods: "confidential_space" }],
    ])("rejects %s with CLAIM_MISSING", (_label, claims) => {
        expectRejected(supportAttributes(claims), "support_attributes", "CLAIM_MISSING");
    });

    it.each<[string, JsonValue]>([
        ["no STABLE", ["LATEST", "USABLE"]],
        ["a string instead of an array", "STABLE"],
        ["EXPERIMENTAL alongside STABLE", ["STABLE", "EXPERIMENTAL"]],
        ["an undocumented value alongside STABLE", ["STABLE", "FUTURE"]],
        ["an empty array", []],
        ["a non-string element", ["STABLE", 42]],
        ["lowercase stable", ["stable"]],
        ["the derivative concatenated form", ["LATEST=STABLE=USABLE"]],
        ["null", null],
    ])("rejects %s with CLAIM_MISMATCH", (_label, value) => {
        expectRejected(
            supportAttributes(withAttributes(value)),
            "support_attributes",
            "CLAIM_MISMATCH",
        );
    });
});
