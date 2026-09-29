// Contract: TrustProfile parsing (spec §15.4, §10.2; API.md §D, §E [CI-4]). Expected red until T-10 merges.
import { describe, expect, it } from "vitest";

import { TrustProfileError, parseTrustProfile } from "@teecustody/core";

import { buildFixture } from "../../support/token-factory.js";

function profileError(input: unknown): TrustProfileError {
    try {
        parseTrustProfile(input);
    } catch (error) {
        if (error instanceof TrustProfileError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected parseTrustProfile to throw");
}

async function productionProfileJson(): Promise<Record<string, unknown>> {
    const fixture = await buildFixture();
    return {
        ...fixture.profileJson,
        profile_kind: "production",
        issuer: "https://confidentialcomputing.googleapis.com",
        discovery_url:
            "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration",
        jwks_origin: "https://www.googleapis.com",
        allowed_hwmodels: ["GCP_AMD_SEV"],
    };
}

describe("parseTrustProfile", () => {
    it("returns a frozen profile with signer keys as bytes", async () => {
        const fixture = await buildFixture();
        const profile = parseTrustProfile(fixture.profileJson);
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.signer_keys)).toBe(true);
        expect(profile.signer_keys[0]?.spki).toBeInstanceOf(Uint8Array);
        expect(profile.signers_required).toBe(2);
    });

    it("rejects unknown fields, so no field can switch a check off (NFR-5, I13)", async () => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, skip_verification: true });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "skip_verification"]);
    });

    it("implements only the OIDC token type (spec §6.1)", async () => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, token_type: "PKI" });
        expect([error.code, error.field]).toEqual(["UNSUPPORTED_TOKEN_TYPE", "token_type"]);
    });

    it("accepts a production profile anchored at the Google issuer", async () => {
        const profile = parseTrustProfile(await productionProfileJson());
        expect(profile.profile_kind).toBe("production");
    });

    it("rejects a production profile with any other issuer (spec §6.2)", async () => {
        const json = { ...(await productionProfileJson()), issuer: "https://tee.example.test" };
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "issuer"]);
    });

    it("rejects a production profile whose JWKS origin is loopback (spec §15.5)", async () => {
        const json = { ...(await productionProfileJson()), jwks_origin: "http://127.0.0.1:8791" };
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_origin"]);
    });

    it("rejects a development profile that claims the Google issuer", async () => {
        const fixture = await buildFixture();
        const json = {
            ...fixture.profileJson,
            issuer: "https://confidentialcomputing.googleapis.com",
        };
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "issuer"]);
    });

    it("rejects ECDSA signer keys in INC-1", async () => {
        const fixture = await buildFixture();
        const signerKeys = fixture.profileJson.signer_keys as readonly Record<string, unknown>[];
        const json = {
            ...fixture.profileJson,
            signer_keys: signerKeys.map((key) => ({ ...key, algorithm: "ECDSA_P256_SHA256" })),
        };
        const error = profileError(json);
        expect([error.code, error.field]).toEqual([
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[0].algorithm",
        ]);
    });

    it("rejects signers_required above the number of signer keys", async () => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, signers_required: 3 });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "signers_required"]);
    });
});
