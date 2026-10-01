// T-10: parseTrustProfile (API.md §D, §E; spec §15.4, §10.2; ADR 0009 rule 9; D-016). Security path.
import { describe, expect, it } from "vitest";

import { parseTrustProfile } from "../../src/attestation/profile.js";
import {
    TrustProfileError,
    isBrandedTrustProfile,
    type TrustProfileErrorCode,
} from "../../src/attestation/types.js";

type ProfileJson = Record<string, unknown>;

const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const KEY_A = "0a".repeat(32);
const KEY_B = "0b".repeat(32);
const KEY_C = "0c".repeat(32);

function developmentJson(): ProfileJson {
    return {
        profile_version: 1,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration",
        jwks_origin: "http://127.0.0.1:8791",
        expected_audience: "https://unit.test/tee",
        token_max_age_s: 3600,
        allowed_hwmodels: ["UNIT_HW"],
        allowed_digests: [`sha256:${"ab".repeat(32)}`],
        signer_keys: [
            { key_id: KEY_A, algorithm: "RSASSA_PSS_SHA256" },
            { key_id: KEY_B, algorithm: "RSASSA_PKCS1V15_SHA256" },
            { key_id: KEY_C, algorithm: "ECDSA_P256_SHA256" },
        ],
        signers_required: 2,
        expected_args_hash: "03".repeat(32),
        expected_env_hash: "04".repeat(32),
    };
}

function productionJson(): ProfileJson {
    return {
        ...developmentJson(),
        profile_kind: "production",
        issuer: GOOGLE_ISSUER,
        discovery_url: `${GOOGLE_ISSUER}/.well-known/openid-configuration`,
        jwks_origin: "https://www.googleapis.com",
        allowed_hwmodels: ["GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX"],
    };
}

describe("parseTrustProfile accepts valid profiles", () => {
    it.each([
        ["development", developmentJson],
        ["production", productionJson],
    ])("returns a frozen, branded %s profile equal to its input", (_kind, build) => {
        const json = build();
        const profile = parseTrustProfile(json);

        expect(isBrandedTrustProfile(profile)).toBe(true);
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(profile.allowed_hwmodels)).toBe(true);
        expect(Object.isFrozen(profile.allowed_digests)).toBe(true);
        expect(Object.isFrozen(profile.signer_keys)).toBe(true);
        expect(profile.signer_keys.every((key) => Object.isFrozen(key))).toBe(true);
        expect({ ...profile }).toEqual(json);
        expect(profile.signer_keys.map((key) => key.algorithm)).toEqual([
            "RSASSA_PSS_SHA256",
            "RSASSA_PKCS1V15_SHA256",
            "ECDSA_P256_SHA256",
        ]);
    });

    it("does not alias or freeze the caller's input", () => {
        const json = developmentJson();
        const profile = parseTrustProfile(json);

        expect(Object.isFrozen(json)).toBe(false);
        expect(profile.signer_keys).not.toBe(json.signer_keys);
        expect(profile.allowed_hwmodels).not.toBe(json.allowed_hwmodels);
        (json.allowed_hwmodels as string[]).push("LATER");
        expect(profile.allowed_hwmodels).toEqual(["UNIT_HW"]);
    });
});

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

type Mutation = ProfileJson | ((json: ProfileJson) => void);

function apply(base: () => ProfileJson, mutation: Mutation): ProfileJson {
    const json = base();
    if (typeof mutation === "function") {
        mutation(json);
        return json;
    }
    return { ...json, ...mutation };
}

function signer(index: number, fields: Record<string, unknown>) {
    return (json: ProfileJson): void => {
        const keys = json.signer_keys as Record<string, unknown>[];
        keys[index] = { ...keys[index], ...fields };
    };
}

function withoutSignerField(index: number, field: string) {
    return (json: ProfileJson): void => {
        const keys = json.signer_keys as Record<string, unknown>[];
        const entry = { ...keys[index] };
        Reflect.deleteProperty(entry, field);
        keys[index] = entry;
    };
}

const PROFILE_KEYS = Object.keys(developmentJson());
const TOO_LONG_AUDIENCE = "a".repeat(2049);
const DIGEST = `sha256:${"ab".repeat(32)}`;
const OTHER_DIGEST = `sha256:${"cd".repeat(32)}`;
const INVALID: TrustProfileErrorCode = "INVALID_PROFILE";

type Row = readonly [
    name: string,
    base: () => ProfileJson,
    mutation: Mutation,
    code: TrustProfileErrorCode,
    field: string,
];

// Criterion 4: every parseTrustProfile rule violated one at a time (SR-3).
const REJECTIONS: Row[] = [
    ...PROFILE_KEYS.map((key): Row => [
        `missing ${key}`,
        developmentJson,
        (json) => {
            Reflect.deleteProperty(json, key);
        },
        INVALID,
        key,
    ]),
    ["profile_version 2", developmentJson, { profile_version: 2 }, INVALID, "profile_version"],
    ['profile_version "1"', developmentJson, { profile_version: "1" }, INVALID, "profile_version"],
    ["profile_kind staging", developmentJson, { profile_kind: "staging" }, INVALID, "profile_kind"],
    ["profile_kind null", developmentJson, { profile_kind: null }, INVALID, "profile_kind"],
    [
        "token_type PKI",
        developmentJson,
        { token_type: "PKI" },
        "UNSUPPORTED_TOKEN_TYPE",
        "token_type",
    ],
    ["token_type 1", productionJson, { token_type: 1 }, "UNSUPPORTED_TOKEN_TYPE", "token_type"],
    ["development issuer not a string", developmentJson, { issuer: 1 }, INVALID, "issuer"],
    ["development issuer not a URL", developmentJson, { issuer: "issuer" }, INVALID, "issuer"],
    [
        "development issuer http:",
        developmentJson,
        { issuer: "http://issuer.unit.test" },
        INVALID,
        "issuer",
    ],
    [
        "development issuer with query",
        developmentJson,
        { issuer: "https://issuer.unit.test/?a=1" },
        INVALID,
        "issuer",
    ],
    [
        "development issuer with fragment",
        developmentJson,
        { issuer: "https://issuer.unit.test/#a" },
        INVALID,
        "issuer",
    ],
    [
        "development discovery_url ftp:",
        developmentJson,
        { discovery_url: "ftp://127.0.0.1/.well-known/openid-configuration" },
        INVALID,
        "discovery_url",
    ],
    [
        "development discovery_url with query",
        developmentJson,
        { discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration?x=1" },
        INVALID,
        "discovery_url",
    ],
    [
        "development discovery_url not a URL",
        developmentJson,
        { discovery_url: "/.well-known/openid-configuration" },
        INVALID,
        "discovery_url",
    ],
    [
        "development discovery_url not a string",
        developmentJson,
        { discovery_url: ["http://127.0.0.1:8791/"] },
        INVALID,
        "discovery_url",
    ],
    [
        "jwks_origin with a path (ruling 3)",
        developmentJson,
        { jwks_origin: "http://127.0.0.1:8791/jwks" },
        INVALID,
        "jwks_origin",
    ],
    [
        "jwks_origin with a trailing slash (ruling 3)",
        developmentJson,
        { jwks_origin: "http://127.0.0.1:8791/" },
        INVALID,
        "jwks_origin",
    ],
    [
        "jwks_origin with a fragment",
        developmentJson,
        { jwks_origin: "http://127.0.0.1:8791#x" },
        INVALID,
        "jwks_origin",
    ],
    [
        "jwks_origin ws:",
        developmentJson,
        { jwks_origin: "ws://127.0.0.1:8791" },
        INVALID,
        "jwks_origin",
    ],
    ["jwks_origin not a string", developmentJson, { jwks_origin: null }, INVALID, "jwks_origin"],
    [
        "production issuer other",
        productionJson,
        { issuer: "https://tee.example.test" },
        INVALID,
        "issuer",
    ],
    [
        "production discovery_url other",
        productionJson,
        { discovery_url: "https://confidentialcomputing.googleapis.com/.well-known/jwks" },
        INVALID,
        "discovery_url",
    ],
    ["empty audience", developmentJson, { expected_audience: "" }, INVALID, "expected_audience"],
    [
        "audience over 2048 chars",
        developmentJson,
        { expected_audience: TOO_LONG_AUDIENCE },
        INVALID,
        "expected_audience",
    ],
    [
        "audience not a string",
        developmentJson,
        { expected_audience: 1 },
        INVALID,
        "expected_audience",
    ],
    ["token_max_age_s 0", developmentJson, { token_max_age_s: 0 }, INVALID, "token_max_age_s"],
    [
        "token_max_age_s 86401",
        developmentJson,
        { token_max_age_s: 86401 },
        INVALID,
        "token_max_age_s",
    ],
    ["token_max_age_s 1.5", developmentJson, { token_max_age_s: 1.5 }, INVALID, "token_max_age_s"],
    [
        'token_max_age_s "60"',
        developmentJson,
        { token_max_age_s: "60" },
        INVALID,
        "token_max_age_s",
    ],
    [
        "hwmodels not an array",
        developmentJson,
        { allowed_hwmodels: "UNIT_HW" },
        INVALID,
        "allowed_hwmodels",
    ],
    ["hwmodels empty", developmentJson, { allowed_hwmodels: [] }, INVALID, "allowed_hwmodels"],
    [
        "hwmodels duplicate (ruling 4)",
        developmentJson,
        { allowed_hwmodels: ["UNIT_HW", "UNIT_HW"] },
        INVALID,
        "allowed_hwmodels[1]",
    ],
    [
        "hwmodel empty string (ruling 5)",
        developmentJson,
        { allowed_hwmodels: ["UNIT_HW", ""] },
        INVALID,
        "allowed_hwmodels[1]",
    ],
    [
        "hwmodel not a string",
        developmentJson,
        { allowed_hwmodels: [7] },
        INVALID,
        "allowed_hwmodels[0]",
    ],
    ["digests not an array", developmentJson, { allowed_digests: {} }, INVALID, "allowed_digests"],
    ["digests empty", developmentJson, { allowed_digests: [] }, INVALID, "allowed_digests"],
    [
        "digest duplicate (ruling 4)",
        developmentJson,
        { allowed_digests: [DIGEST, OTHER_DIGEST, DIGEST] },
        INVALID,
        "allowed_digests[2]",
    ],
    [
        "digest uppercase hex",
        developmentJson,
        { allowed_digests: [DIGEST.toUpperCase().replace("SHA256", "sha256")] },
        INVALID,
        "allowed_digests[0]",
    ],
    [
        "digest without prefix",
        developmentJson,
        { allowed_digests: ["ab".repeat(32)] },
        INVALID,
        "allowed_digests[0]",
    ],
    [
        "digest with trailing newline",
        developmentJson,
        { allowed_digests: [`${DIGEST}\n`] },
        INVALID,
        "allowed_digests[0]",
    ],
    [
        "digest not a string",
        developmentJson,
        { allowed_digests: [null] },
        INVALID,
        "allowed_digests[0]",
    ],
    ["signer_keys not an array", developmentJson, { signer_keys: {} }, INVALID, "signer_keys"],
    ["signer_keys empty", developmentJson, { signer_keys: [] }, INVALID, "signer_keys"],
    ["signer entry null", developmentJson, { signer_keys: [null] }, INVALID, "signer_keys[0]"],
    ["signer entry array", developmentJson, { signer_keys: [[KEY_A]] }, INVALID, "signer_keys[0]"],
    [
        "signer entry missing key_id",
        developmentJson,
        withoutSignerField(1, "key_id"),
        INVALID,
        "signer_keys[1].key_id",
    ],
    [
        "signer entry missing algorithm",
        developmentJson,
        withoutSignerField(2, "algorithm"),
        INVALID,
        "signer_keys[2].algorithm",
    ],
    [
        "key_id not a string",
        developmentJson,
        signer(0, { key_id: 1 }),
        INVALID,
        "signer_keys[0].key_id",
    ],
    [
        "key_id duplicate (ruling 4)",
        developmentJson,
        signer(1, { key_id: KEY_A }),
        INVALID,
        "signer_keys[1].key_id",
    ],
    [
        "algorithm not a string",
        developmentJson,
        signer(0, { algorithm: null }),
        INVALID,
        "signer_keys[0].algorithm",
    ],
    ["signers_required 0", developmentJson, { signers_required: 0 }, INVALID, "signers_required"],
    [
        "signers_required above signer count",
        developmentJson,
        { signers_required: 4 },
        INVALID,
        "signers_required",
    ],
    [
        "signers_required 1.5",
        developmentJson,
        { signers_required: 1.5 },
        INVALID,
        "signers_required",
    ],
    [
        'signers_required "2"',
        developmentJson,
        { signers_required: "2" },
        INVALID,
        "signers_required",
    ],
    ...(["expected_args_hash", "expected_env_hash"] as const).flatMap((field): Row[] => [
        [`${field} uppercase`, developmentJson, { [field]: "AB".repeat(32) }, INVALID, field],
        [`${field} 63 chars`, developmentJson, { [field]: "a".repeat(63) }, INVALID, field],
        [`${field} 65 chars`, developmentJson, { [field]: "a".repeat(65) }, INVALID, field],
        [`${field} not a string`, developmentJson, { [field]: 0 }, INVALID, field],
    ]),
];

describe("parseTrustProfile rejects each rule violation with its code and field (SR-3)", () => {
    it.each(REJECTIONS)("%s", (_name, base, mutation, code, field) => {
        const error = profileError(apply(base, mutation));
        expect([error.code, error.field]).toEqual([code, field]);
        expect(error.message).toBe(`${field}: ${code}`);
    });

    it.each([
        ["null", null],
        ["an array", [developmentJson()]],
        ["a string", "{}"],
        [
            "a class instance",
            Object.assign(Object.create({ inherited: true }) as object, developmentJson()),
        ],
    ])('rejects a root that is %s with field ""', (_name, input) => {
        const error = profileError(input);
        expect([error.code, error.field]).toEqual([INVALID, ""]);
    });

    it.each([
        [
            "dev issuer with a path (ruling 3)",
            developmentJson,
            { issuer: "https://issuer.unit.test/tenant" },
        ],
        [
            "dev discovery on localhost",
            developmentJson,
            { discovery_url: "http://localhost:8791/d" },
        ],
        ["dev JWKS on [::1]", developmentJson, { jwks_origin: "http://[::1]:8791" }],
        [
            "dev JWKS over https loopback",
            developmentJson,
            { jwks_origin: "https://127.0.0.1:8443" },
        ],
        [
            "boundary audience and age",
            developmentJson,
            { expected_audience: "a".repeat(2048), token_max_age_s: 86400 },
        ],
        ["minimum age and signers", developmentJson, { token_max_age_s: 1, signers_required: 1 }],
        ["signers_required equal to signer count", developmentJson, { signers_required: 3 }],
        [
            "null-prototype root",
            developmentJson,
            (json: ProfileJson) => {
                Object.setPrototypeOf(json, null);
            },
        ],
    ] as const)("accepts %s", (_name, base, mutation) => {
        const json = apply(base, mutation);
        expect(parseTrustProfile(json).profile_kind).toBe(json.profile_kind);
    });
});

// Criterion 5 (NFR-5 / I13): no profile field can switch a check off; unknown keys are rejected at every level.
describe("parseTrustProfile rejects unknown keys", () => {
    it.each([
        ["skip_verification", { skip_verification: true }, "skip_verification"],
        ["skip_verification false", { skip_verification: false }, "skip_verification"],
        ["allow_debug", { allow_debug: true }, "allow_debug"],
        ["pinned_root (PKI not implemented)", { pinned_root: "AAAA" }, "pinned_root"],
    ] as const)("%s at the root", (_name, extra, field) => {
        const error = profileError({ ...developmentJson(), ...extra });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", field]);
    });

    it("an unknown key in a production profile", () => {
        const error = profileError({ ...productionJson(), skip_verification: true });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "skip_verification"]);
    });

    it("an unknown key in a signer entry", () => {
        const error = profileError(apply(developmentJson, signer(2, { optional: true })));
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "signer_keys[2].optional"]);
    });
});

// Criterion 6 (SR-1 ADR 0009 conditions; SR-7 dev/prod anchor separation; rulings 1 and 2; FACTS F-07, F-09).
const ANCHOR_REJECTIONS: readonly (readonly [string, () => ProfileJson, ProfileJson, string])[] = [
    [
        "production loopback http: discovery",
        productionJson,
        { discovery_url: "http://127.0.0.1:8791/.well-known/openid-configuration" },
        "discovery_url",
    ],
    [
        "production http: discovery",
        productionJson,
        {
            discovery_url:
                "http://confidentialcomputing.googleapis.com/.well-known/openid-configuration",
        },
        "discovery_url",
    ],
    [
        "production loopback JWKS",
        productionJson,
        { jwks_origin: "http://127.0.0.1:8791" },
        "jwks_origin",
    ],
    [
        "production http: JWKS",
        productionJson,
        { jwks_origin: "http://www.googleapis.com" },
        "jwks_origin",
    ],
    [
        "production other JWKS",
        productionJson,
        { jwks_origin: "https://keys.example.test" },
        "jwks_origin",
    ],
    [
        "production JWKS on the issuer origin",
        productionJson,
        { jwks_origin: GOOGLE_ISSUER },
        "jwks_origin",
    ],
    [
        "production hwmodel SIMULATED",
        productionJson,
        { allowed_hwmodels: ["GCP_AMD_SEV", "SIMULATED"] },
        "allowed_hwmodels[1]",
    ],
    [
        "production hwmodel GCP_SHIELDED_VM",
        productionJson,
        { allowed_hwmodels: ["GCP_SHIELDED_VM"] },
        "allowed_hwmodels[0]",
    ],
    [
        "production hwmodel INTEL_TDX",
        productionJson,
        { allowed_hwmodels: ["INTEL_TDX"] },
        "allowed_hwmodels[0]",
    ],
    ["development Google issuer", developmentJson, { issuer: GOOGLE_ISSUER }, "issuer"],
    [
        "development Google issuer with trailing slash (ruling 2)",
        developmentJson,
        { issuer: `${GOOGLE_ISSUER}/` },
        "issuer",
    ],
    [
        "development Google issuer with a path (ruling 2)",
        developmentJson,
        { issuer: `${GOOGLE_ISSUER}/tenant` },
        "issuer",
    ],
    [
        "development Google issuer with :443 (ruling 2)",
        developmentJson,
        { issuer: "https://confidentialcomputing.googleapis.com:443" },
        "issuer",
    ],
    [
        "development non-loopback http: discovery",
        developmentJson,
        { discovery_url: "http://sim.example.test:8791/.well-known/openid-configuration" },
        "discovery_url",
    ],
    [
        "development non-loopback http: JWKS",
        developmentJson,
        { jwks_origin: "http://10.0.0.1:8791" },
        "jwks_origin",
    ],
    [
        "development non-loopback https: discovery (ruling 1)",
        developmentJson,
        { discovery_url: `${GOOGLE_ISSUER}/.well-known/openid-configuration` },
        "discovery_url",
    ],
    [
        "development non-loopback https: JWKS (ruling 1)",
        developmentJson,
        { jwks_origin: "https://www.googleapis.com" },
        "jwks_origin",
    ],
    [
        "development issuer with userinfo",
        developmentJson,
        { issuer: "https://user:secret@issuer.unit.test" },
        "issuer",
    ],
    [
        "development issuer with a username only",
        developmentJson,
        { issuer: "https://user@issuer.unit.test" },
        "issuer",
    ],
    [
        "development discovery with userinfo",
        developmentJson,
        { discovery_url: "http://user:secret@127.0.0.1:8791/.well-known/openid-configuration" },
        "discovery_url",
    ],
    [
        "development discovery with a password only",
        developmentJson,
        { discovery_url: "http://:secret@127.0.0.1:8791/.well-known/openid-configuration" },
        "discovery_url",
    ],
    [
        "development JWKS with userinfo",
        developmentJson,
        { jwks_origin: "http://user@127.0.0.1:8791" },
        "jwks_origin",
    ],
];

describe("parseTrustProfile keeps development and production anchors apart", () => {
    it.each(ANCHOR_REJECTIONS)("%s", (_name, base, override, field) => {
        const error = profileError({ ...base(), ...override });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", field]);
    });

    it.each([["GCP_AMD_SEV"], ["GCP_AMD_SEV_ES"], ["GCP_INTEL_TDX"]])(
        "accepts production hwmodel %s (F-09)",
        (hwmodel) => {
            const profile = parseTrustProfile({ ...productionJson(), allowed_hwmodels: [hwmodel] });
            expect(profile.allowed_hwmodels).toEqual([hwmodel]);
        },
    );
});
