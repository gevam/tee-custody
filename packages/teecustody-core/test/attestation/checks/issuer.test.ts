// §6.2 issuer check (T-11; SR-1, SR-11).
import { describe, expect, it } from "vitest";

import { checkIssuer } from "../../../src/attestation/checks/issuer.js";
import {
    AttestationError,
    brandTrustProfile,
    type ParsedToken,
    type TrustProfile,
} from "../../../src/attestation/types.js";
import type { JsonObject } from "../../../src/json.js";

const ISSUER = "https://confidentialcomputing.googleapis.com";

const PROFILE: TrustProfile = brandTrustProfile({
    profile_version: 1,
    profile_kind: "production",
    token_type: "OIDC",
    issuer: ISSUER,
    discovery_url: `${ISSUER}/.well-known/openid-configuration`,
    jwks_origin: "https://www.googleapis.com",
    expected_audience: "https://unit.test/tee",
    token_max_age_s: 3600,
    allowed_hwmodels: ["GCP_AMD_SEV"],
    allowed_digests: [`sha256:${"ab".repeat(32)}`],
    signer_keys: [{ key_id: "01".repeat(32), algorithm: "RSASSA_PSS_SHA256" }],
    signers_required: 1,
    expected_args_hash: "03".repeat(32),
    expected_env_hash: "04".repeat(32),
});

function tokenWithClaims(claims: JsonObject): ParsedToken {
    return {
        header: { alg: "RS256", kid: "k" },
        claims,
        signingInput: new Uint8Array([0x61, 0x2e, 0x62]),
        signature: new Uint8Array([1]),
    };
}

// Criterion 8 / SR-11: the message is exactly `check: CODE` and nothing else rides on the error.
function expectNoContent(error: AttestationError, message: string): void {
    expect(error.message).toBe(message);
    expect(error.cause).toBeUndefined();
    expect(Object.keys(error).sort()).toEqual(["check", "code"]);
}

function thrown(run: () => void): AttestationError {
    try {
        run();
    } catch (error: unknown) {
        if (error instanceof AttestationError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected checkIssuer to throw");
}

describe("checkIssuer (criterion 7)", () => {
    it("passes when iss equals the profile issuer", () => {
        expect(() => {
            checkIssuer(tokenWithClaims({ iss: ISSUER, aud: "x" }), PROFILE);
        }).not.toThrow();
    });

    it("rejects an absent iss as CLAIM_MISSING", () => {
        const error = thrown(() => {
            checkIssuer(tokenWithClaims({ aud: "x" }), PROFILE);
        });
        expect([error.code, error.check]).toEqual(["CLAIM_MISSING", "issuer"]);
        expectNoContent(error, "issuer: CLAIM_MISSING");
    });

    it.each([
        ["a different issuer", `${ISSUER}.evil.test`],
        ["a non-string iss", [ISSUER]],
        ["a null iss", null],
        ["a trailing-slash issuer", `${ISSUER}/`],
        ["an issuer differing in case", ISSUER.toUpperCase()],
    ])("rejects %s as CLAIM_MISMATCH", (_label, iss) => {
        const error = thrown(() => {
            checkIssuer(tokenWithClaims({ iss }), PROFILE);
        });
        expect([error.code, error.check]).toEqual(["CLAIM_MISMATCH", "issuer"]);
        expectNoContent(error, "issuer: CLAIM_MISMATCH");
    });
});
