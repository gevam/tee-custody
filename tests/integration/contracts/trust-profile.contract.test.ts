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
    it("returns a frozen profile whose signer entries are {key_id, algorithm}", async () => {
        const fixture = await buildFixture();
        const profile = parseTrustProfile(fixture.profileJson);
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.signer_keys)).toBe(true);
        expect(Object.keys(profile.signer_keys[0] ?? {}).sort()).toEqual(["algorithm", "key_id"]);
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

    it("accepts every F-11 signer algorithm and rejects any other (D-016)", async () => {
        const fixture = await buildFixture();
        const signerKeys = fixture.profileJson.signer_keys as readonly Record<string, unknown>[];
        for (const algorithm of [
            "RSASSA_PSS_SHA256",
            "RSASSA_PKCS1V15_SHA256",
            "ECDSA_P256_SHA256",
        ]) {
            const json = {
                ...fixture.profileJson,
                signer_keys: signerKeys.map((key) => ({ ...key, algorithm })),
            };
            expect(parseTrustProfile(json).signer_keys[0]?.algorithm).toBe(algorithm);
        }
        const error = profileError({
            ...fixture.profileJson,
            signer_keys: signerKeys.map((key) => ({ ...key, algorithm: "ED25519" })),
        });
        expect([error.code, error.field]).toEqual([
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[0].algorithm",
        ]);
    });

    it("rejects public-key bytes in signer entries; the profile carries key_ids only (D-016)", async () => {
        const fixture = await buildFixture();
        const signerKeys = fixture.profileJson.signer_keys as readonly Record<string, unknown>[];
        const error = profileError({
            ...fixture.profileJson,
            signer_keys: signerKeys.map((key) => ({ ...key, spki: "AAAA" })),
        });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "signer_keys[0].spki"]);
    });

    it("rejects key_ids that are not 64 lowercase hex characters (SR-1 D-016 (f))", async () => {
        const fixture = await buildFixture();
        const signerKeys = fixture.profileJson.signer_keys as readonly Record<string, unknown>[];
        const first = signerKeys[0]?.key_id as string;
        for (const keyId of [first.toUpperCase(), first.slice(1), `${first}0`, `sha256:${first}`]) {
            const error = profileError({
                ...fixture.profileJson,
                signer_keys: [{ ...signerKeys[0], key_id: keyId }, ...signerKeys.slice(1)],
            });
            expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "signer_keys[0].key_id"]);
        }
    });

    it("pins the production JWKS origin and confidential hwmodels (F-07, F-09)", async () => {
        const base = await productionProfileJson();
        const origin = profileError({ ...base, jwks_origin: "https://keys.example.test" });
        expect([origin.code, origin.field]).toEqual(["INVALID_PROFILE", "jwks_origin"]);
        const shielded = profileError({ ...base, allowed_hwmodels: ["GCP_SHIELDED_VM"] });
        expect([shielded.code, shielded.field]).toEqual(["INVALID_PROFILE", "allowed_hwmodels[0]"]);
        expect(
            parseTrustProfile({ ...base, allowed_hwmodels: ["GCP_AMD_SEV_ES", "GCP_INTEL_TDX"] })
                .profile_kind,
        ).toBe("production");
    });

    it("rejects signers_required above the number of signer keys", async () => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, signers_required: 3 });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "signers_required"]);
    });
});
