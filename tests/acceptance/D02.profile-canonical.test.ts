// D-02 (SR-1 / SR-3), updated for D-043: the development jwks_uri must already be canonical.
// Red on v1 Core (v1 profile fields); green on the MU-1 branch.
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

const rejects = (override: Record<string, unknown>): void => {
    let caught: unknown;
    try {
        parseTrustProfile({ ...dev(), ...override });
    } catch (error) {
        caught = error;
    }
    expect(caught).toBeInstanceOf(TrustProfileError);
    expect((caught as TrustProfileError).code).toBe("INVALID_PROFILE");
    expect((caught as TrustProfileError).field).toBe("jwks_uri");
};

describe("D-02 given a non-canonical loopback spelling in a development profile", () => {
    it("the canonical profile still parses", () => {
        expect(() => parseTrustProfile(dev())).not.toThrow();
    });

    it.each([
        "http://0x7f.1:8791/jwks",
        "http://127.1:8791/jwks",
        "http://2130706433:8791/jwks",
        "http://0177.0.0.1:8791/jwks",
        "http://127.0.0.1:80/jwks",
        "https://127.0.0.1:443/jwks",
        "http://127.0.0.1\\@evil.test/jwks",
        "http://127.0.0.1:8791//jwks",
        "HTTP://127.0.0.1:8791/jwks",
        "http://127.0.0.1:8791/jwks/",
        "http://127.0.0.1:8791/JWKS",
        "http://127.0.0.1:8791/attacker/jwks",
    ])("rejects jwks_uri %s", (url) => {
        rejects({ jwks_uri: url });
    });
});
