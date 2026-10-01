import { describe, expect, it } from "vitest";

import { checkAudience } from "../../../src/attestation/checks/claims.js";
import {
    AttestationError,
    brandTrustProfile,
    type AttestationCheckId,
    type AttestationErrorCode,
    type ParsedToken,
    type TrustProfile,
} from "../../../src/attestation/types.js";
import type { JsonObject } from "../../../src/json.js";

const AUDIENCE = "https://unit.test/tee";

const PROFILE: TrustProfile = brandTrustProfile({
    profile_version: 1,
    profile_kind: "development",
    token_type: "OIDC",
    issuer: "https://issuer.unit.test",
    discovery_url: "http://127.0.0.1:1/.well-known/openid-configuration",
    jwks_origin: "http://127.0.0.1:1",
    expected_audience: AUDIENCE,
    token_max_age_s: 3600,
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
