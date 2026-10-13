// Contract: TrustProfile parsing (spec §15.4, §10.2; API.md §D, §E [CI-4]). Amended by T-33 for trust profile v2
// (D-043, ADR 0012; INC-2-API §16.1, §16.9 C3, C4): a pinned jwks_uri replaces discovery_url and jwks_origin.
import { describe, expect, it } from "vitest";

import { TrustProfileError, parseTrustProfile } from "@teecustody/core";

import { DISCOVERY_URL, JWKS_ORIGIN, JWKS_URL, buildFixture } from "../../support/token-factory.js";

// FACTS F-07 (re-confirmed 2026-10-13).
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";

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
        jwks_uri: GOOGLE_JWKS_URI,
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

    it("rejects a production profile whose jwks_uri is loopback (spec §15.5)", async () => {
        const json = { ...(await productionProfileJson()), jwks_uri: JWKS_URL };
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
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

    it("pins the production jwks_uri and confidential hwmodels (F-07, F-09)", async () => {
        const base = await productionProfileJson();
        const origin = profileError({ ...base, jwks_uri: "https://keys.example.test/jwks" });
        expect([origin.code, origin.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
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

// C4: only v2 parses; the version is checked before the key set.
describe("parseTrustProfile accepts only trust profile v2 (C4)", () => {
    it("the fixture profile is v2 with jwks_uri JWKS_URL and no discovery_url or jwks_origin", async () => {
        const fixture = await buildFixture();
        expect(fixture.profileJson.profile_version).toBe(2);
        expect(fixture.profileJson.jwks_uri).toBe(JWKS_URL);
        expect(Object.keys(fixture.profileJson)).not.toContain("discovery_url");
        expect(Object.keys(fixture.profileJson)).not.toContain("jwks_origin");
        expect(fixture.profile.jwks_uri).toBe(JWKS_URL);
    });

    it("rejects the INC-1 v1 profile at profile_version", async () => {
        const fixture = await buildFixture();
        const v1: Record<string, unknown> = {
            ...fixture.profileJson,
            profile_version: 1,
            discovery_url: DISCOVERY_URL,
            jwks_origin: JWKS_ORIGIN,
        };
        delete v1.jwks_uri;
        const error = profileError(v1);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "profile_version"]);
    });

    it.each([
        ["discovery_url", DISCOVERY_URL],
        ["jwks_origin", JWKS_ORIGIN],
    ])("rejects v2 plus %s at that field", async (field, value) => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, [field]: value });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", field]);
    });

    it("rejects v2 without jwks_uri at jwks_uri", async () => {
        const fixture = await buildFixture();
        const json: Record<string, unknown> = { ...fixture.profileJson };
        delete json.jwks_uri;
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });
});

// C3: jwks_uri is an exact, canonical string.
describe("parseTrustProfile pins jwks_uri (C3)", () => {
    it.each([
        [`${GOOGLE_JWKS_URI}/`],
        [`${GOOGLE_JWKS_URI}?`],
        [`${GOOGLE_JWKS_URI}#`],
        [GOOGLE_JWKS_URI.replace("www.", "WWW.")],
        [GOOGLE_JWKS_URI.replace(".com/", ".com:443/")],
        [GOOGLE_JWKS_URI.replace("@", "%40")],
        [GOOGLE_JWKS_URI.replace("signer@", "other@")],
        [` ${GOOGLE_JWKS_URI}`],
    ])("production rejects %j", async (jwksUri) => {
        const error = profileError({ ...(await productionProfileJson()), jwks_uri: jwksUri });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });

    it.each([
        [`${JWKS_ORIGIN}/attacker/jwks`],
        [`${JWKS_ORIGIN}/jwks/`],
        [`${JWKS_ORIGIN}//jwks`],
        [`${JWKS_ORIGIN}/JWKS`],
        ["http://127.1:8791/jwks"],
        ["http://127.0.0.1:80/jwks"],
        ["http://sim.example.test:8791/jwks"],
        [`${JWKS_URL}?x=1`],
    ])("development rejects %j", async (jwksUri) => {
        const fixture = await buildFixture();
        const error = profileError({ ...fixture.profileJson, jwks_uri: jwksUri });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });

    it("a parsed production profile carries the canonical F-07 string (C5)", async () => {
        const profile = parseTrustProfile(await productionProfileJson());
        expect(profile.jwks_uri).toBe(GOOGLE_JWKS_URI);
        expect(new URL(profile.jwks_uri).href).toBe(profile.jwks_uri);
    });
});
