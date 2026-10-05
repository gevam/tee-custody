// D-02 (SR-1 / SR-3): development trust profile URLs must already be in canonical form.
// Expected failure on trunk: parseTrustProfile accepts the non-canonical loopback literals.
import { TrustProfileError, parseTrustProfile } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { ARGS_HASH, ENV_HASH, IMAGE_DIGEST, ISSUER } from "../support/token-factory.js";

const KEY_A = "a1".repeat(32);
const KEY_B = "b2".repeat(32);
const WK = "/.well-known/openid-configuration";

const dev = (): Record<string, unknown> => ({
    profile_version: 1,
    profile_kind: "development",
    token_type: "OIDC",
    issuer: ISSUER,
    discovery_url: `http://127.0.0.1:8791${WK}`,
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

const rejects = (override: Record<string, unknown>): void => {
    let caught: unknown;
    try {
        parseTrustProfile({ ...dev(), ...override });
    } catch (error) {
        caught = error;
    }
    expect(caught).toBeInstanceOf(TrustProfileError);
    expect((caught as TrustProfileError).code).toBe("INVALID_PROFILE");
};

describe("D-02 given a non-canonical loopback spelling in a development profile", () => {
    it("the canonical profile still parses", () => {
        expect(() => parseTrustProfile(dev())).not.toThrow();
    });

    it.each([
        `http://0x7f.1${WK}`,
        `http://127.1${WK}`,
        `http://2130706433${WK}`,
        `http://0177.0.0.1${WK}`,
        `http://127.0.0.1:80${WK}`,
        `http://127.0.0.1\\@evil.test${WK}`,
        `http://127.0.0.1:8791//.well-known/../.well-known/openid-configuration`,
        `HTTP://127.0.0.1:8791${WK}`,
    ])("rejects discovery_url %s", (url) => {
        rejects({ discovery_url: url });
    });

    it.each([
        "http://0x7f.1:8791",
        "http://127.1:8791",
        "http://2130706433:8791",
        "http://127.0.0.1:8791/",
        "http://127.0.0.1\\@evil.test:8791",
    ])("rejects jwks_origin %s", (origin) => {
        rejects({ jwks_origin: origin });
    });
});
