// T-10, T-33: parseTrustProfile (API.md §D, §E; INC-2-API §16.1; spec §15.4, §10.2; ADR 0009 rule 9, ADR 0012;
// D-016, D-043). Security path.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { parseTrustProfile } from "../../src/attestation/profile.js";
import {
    TrustProfileError,
    isBrandedTrustProfile,
    type TrustProfileErrorCode,
} from "../../src/attestation/types.js";
import { decodeCanonical } from "../../src/wire/cbor.js";

type ProfileJson = Record<string, unknown>;

const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
// FACTS F-07, re-confirmed 2026-10-13 against the live discovery document.
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
const DEV_JWKS_URI = "http://127.0.0.1:8791/jwks";
const KEY_A = "0a".repeat(32);
const KEY_B = "0b".repeat(32);
const KEY_C = "0c".repeat(32);

function developmentJson(): ProfileJson {
    return {
        profile_version: 2,
        profile_kind: "development",
        token_type: "OIDC",
        issuer: "https://issuer.unit.test",
        jwks_uri: DEV_JWKS_URI,
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
        jwks_uri: GOOGLE_JWKS_URI,
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
    ["profile_version 1", developmentJson, { profile_version: 1 }, INVALID, "profile_version"],
    ["profile_version 3", developmentJson, { profile_version: 3 }, INVALID, "profile_version"],
    ['profile_version "2"', developmentJson, { profile_version: "2" }, INVALID, "profile_version"],
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
        "production issuer other",
        productionJson,
        { issuer: "https://tee.example.test" },
        INVALID,
        "issuer",
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

// Criterion 6a (SR-1 D-016 (f), (i) as ruled): signer entries are {key_id, algorithm} with no key bytes.
describe("parseTrustProfile enforces the signer entry shape", () => {
    it.each([
        [
            "an spki member",
            signer(0, { spki: "MCowBQYDK2VwAyEA" }),
            "INVALID_PROFILE",
            "signer_keys[0].spki",
        ],
        [
            "a 63-char key_id",
            signer(1, { key_id: KEY_B.slice(1) }),
            "INVALID_PROFILE",
            "signer_keys[1].key_id",
        ],
        [
            "a 65-char key_id",
            signer(1, { key_id: `${KEY_B}0` }),
            "INVALID_PROFILE",
            "signer_keys[1].key_id",
        ],
        [
            "an uppercase key_id",
            signer(0, { key_id: "0A".repeat(32) }),
            "INVALID_PROFILE",
            "signer_keys[0].key_id",
        ],
        [
            "a sha256:-prefixed key_id",
            signer(0, { key_id: `sha256:${KEY_A}` }),
            "INVALID_PROFILE",
            "signer_keys[0].key_id",
        ],
        ["an empty key_id", signer(0, { key_id: "" }), "INVALID_PROFILE", "signer_keys[0].key_id"],
        [
            "algorithm ED25519",
            signer(2, { algorithm: "ED25519" }),
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[2].algorithm",
        ],
        [
            "algorithm HMAC_SHA256",
            signer(0, { algorithm: "HMAC_SHA256" }),
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[0].algorithm",
        ],
        [
            "algorithm in lower case",
            signer(0, { algorithm: "rsassa_pss_sha256" }),
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[0].algorithm",
        ],
        [
            "algorithm RS256 (the JWS name, not an F-11 value)",
            signer(0, { algorithm: "RS256" }),
            "UNSUPPORTED_ALGORITHM",
            "signer_keys[0].algorithm",
        ],
    ] as const)("rejects %s", (_name, mutation, code, field) => {
        const error = profileError(apply(developmentJson, mutation));
        expect([error.code, error.field]).toEqual([code, field]);
    });
});

// T-24 (D-02, B-02, B-03; SR-1, SR-3): development anchors are accepted only in canonical form.

function expectRejected(override: ProfileJson, field: string): void {
    const error = profileError({ ...developmentJson(), ...override });
    expect([error.code, error.field]).toEqual(["INVALID_PROFILE", field]);
    expect(error.message).toBe(`${field}: INVALID_PROFILE`);
}

describe("parseTrustProfile requires a canonical development issuer origin (T-24 criterion 2)", () => {
    it.each([
        "https://confidentialcomputing.googleapis.com.",
        "https://tee-sim.localhost/",
        "https://tee-sim.localhost/p",
        "https://TEE-SIM.localhost",
        "https://tee-sim.localhost:443",
        "https://u@tee-sim.localhost",
        "https://tee-sim.localhost.",
    ])("rejects %s", (issuer) => {
        expectRejected({ issuer }, "issuer");
    });
});

const SUITE_URL = new URL("../../../../spec/vectors/attestation/suite.cbor", import.meta.url);
const SUITE_LIMITS = { maxBytes: 1_048_576, maxDepth: 8, maxItems: 16_384 };

function suiteProfileJson(): ProfileJson {
    const root = decodeCanonical(new Uint8Array(readFileSync(SUITE_URL)), SUITE_LIMITS);
    if (!(root instanceof Map)) {
        throw new Error("expected the vector suite to be a CBOR map");
    }
    const json: unknown = root.get("profile_json");
    if (typeof json !== "string") {
        throw new Error("expected profile_json to be a text string");
    }
    return JSON.parse(json) as ProfileJson;
}

describe("parseTrustProfile accepts canonical anchors (T-24 criteria 3 and 4)", () => {
    it.each(["https://tee-sim.localhost", "https://issuer.unit.test"])(
        "accepts issuer %s",
        (issuer) => {
            expect(parseTrustProfile({ ...developmentJson(), issuer }).issuer).toBe(issuer);
        },
    );

    it.each([
        "http://127.0.0.1:8791/jwks",
        "http://[::1]:8791/jwks",
        "http://localhost:8791/jwks",
        "https://127.0.0.1:8443/jwks",
        "http://127.0.0.1/jwks",
    ])("accepts jwks_uri %s and returns the input string", (url) => {
        const profile = parseTrustProfile({ ...developmentJson(), jwks_uri: url });
        expect(profile.jwks_uri).toBe(url);
        expect(profile.jwks_uri).toBe(new URL(url).href);
    });

    it("accepts the vector suite's development profile_json unchanged", () => {
        const json = suiteProfileJson();
        const profile = parseTrustProfile(json);
        expect(profile.profile_kind).toBe("development");
        expect({ ...profile }).toEqual(json);
    });

    it("accepts the production profile with Google anchors unchanged", () => {
        const profile = parseTrustProfile(productionJson());
        expect([profile.issuer, profile.jwks_uri]).toEqual([GOOGLE_ISSUER, GOOGLE_JWKS_URI]);
    });
});

// T-33 C4 (INC-2-API §16.1 step 2; D-043, D-047 Q9e): only v2 parses, and the version is checked before the
// key set, so every v1 profile fails at profile_version and never at an unknown-key field.
// The INC-1 API.md §E v1 JSON verbatim, with its placeholders filled in.
const INC1_V1_PROFILE_JSON = `{"profile_version": 1, "profile_kind": "development", "token_type": "OIDC",
 "issuer": "https://tee-sim.localhost",
 "discovery_url": "http://127.0.0.1:8791/.well-known/openid-configuration",
 "jwks_origin": "http://127.0.0.1:8791",
 "expected_audience": "https://example.test/tee", "token_max_age_s": 3600,
 "allowed_hwmodels": ["SIMULATED"], "allowed_digests": ["sha256:${"ab".repeat(32)}"],
 "signer_keys": [{"key_id": "${KEY_A}", "algorithm": "RSASSA_PSS_SHA256"}],
 "signers_required": 2, "expected_args_hash": "${"03".repeat(32)}", "expected_env_hash": "${"04".repeat(32)}"}`;

describe("parseTrustProfile accepts only trust profile v2 (T-33 C4)", () => {
    it("rejects the exact INC-1 v1 JSON at profile_version", () => {
        const error = profileError(JSON.parse(INC1_V1_PROFILE_JSON));
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "profile_version"]);
    });

    it("rejects a v1 profile at profile_version even with a v2 key set", () => {
        const error = profileError({ ...developmentJson(), profile_version: 1, extra: true });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "profile_version"]);
    });

    it.each([
        ["discovery_url", "http://127.0.0.1:8791/.well-known/openid-configuration"],
        ["jwks_origin", "http://127.0.0.1:8791"],
    ])("rejects v2 plus %s at that field", (field, value) => {
        const error = profileError({ ...developmentJson(), [field]: value });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", field]);
    });

    it.each([
        ["development", developmentJson],
        ["production", productionJson],
    ])("rejects a %s v2 profile without jwks_uri at jwks_uri", (_kind, build) => {
        const json = build();
        Reflect.deleteProperty(json, "jwks_uri");
        const error = profileError(json);
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
    });

    it("rejects an absent profile_version when Object.prototype.profile_version is 2, before an unknown key", () => {
        const json: ProfileJson = { ...developmentJson(), extra: true };
        Reflect.deleteProperty(json, "profile_version");
        Object.defineProperty(Object.prototype, "profile_version", {
            value: 2,
            configurable: true,
        });
        try {
            const error = profileError(json);
            expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "profile_version"]);
        } finally {
            Reflect.deleteProperty(Object.prototype, "profile_version");
        }
    });
});

// T-33 C5 (INC-2-API §16.9): the pinned production jwks_uri is already in WHATWG canonical form in Node 22,
// so a canonical-form check can never disagree with the Core constant.
describe("the production jwks_uri constant is canonical (T-33 C5)", () => {
    it("new URL(GOOGLE_JWKS_URI).href === GOOGLE_JWKS_URI, read through a parsed production profile", () => {
        expect(Number(process.versions.node.split(".")[0])).toBeGreaterThanOrEqual(22);
        const { jwks_uri: pinned } = parseTrustProfile(productionJson());
        expect(pinned).toBe(GOOGLE_JWKS_URI);
        expect(new URL(pinned).href).toBe(pinned);
    });
});

// T-33 C3 (INC-2-API §16.1 step 5, §16.9 C3; ADR 0012 rule 1): jwks_uri is an exact, canonical URL string.
const NOT_A_STRING_OR_TOO_LONG: readonly (readonly [string, unknown])[] = [
    ["empty", ""],
    ["a number", 42],
    ["null", null],
    ["an array", [GOOGLE_JWKS_URI]],
    ["an object", { href: GOOGLE_JWKS_URI }],
    ["2049 characters", `${GOOGLE_JWKS_URI}${"a".repeat(2049 - GOOGLE_JWKS_URI.length)}`],
];

const PRODUCTION_JWKS_URI_VARIANTS: readonly (readonly [string, unknown])[] = [
    [
        "another service account path",
        "https://www.googleapis.com/service_accounts/v1/metadata/jwk/other@confidentialspace-sign.iam.gserviceaccount.com",
    ],
    ["a trailing /", `${GOOGLE_JWKS_URI}/`],
    ["an empty query", `${GOOGLE_JWKS_URI}?`],
    ["a query", `${GOOGLE_JWKS_URI}?x=1`],
    ["an empty fragment", `${GOOGLE_JWKS_URI}#`],
    ["a fragment", `${GOOGLE_JWKS_URI}#x`],
    ["host WWW.googleapis.com", GOOGLE_JWKS_URI.replace("www.", "WWW.")],
    ["path segment /Service_accounts/", GOOGLE_JWKS_URI.replace("/service_", "/Service_")],
    ["scheme http:", GOOGLE_JWKS_URI.replace("https:", "http:")],
    ["an explicit :443", GOOGLE_JWKS_URI.replace(".com/", ".com:443/")],
    ["userinfo", GOOGLE_JWKS_URI.replace("https://", "https://u:p@")],
    ["a username only", GOOGLE_JWKS_URI.replace("https://", "https://u@")],
    ["%40 in place of @", GOOGLE_JWKS_URI.replace("@", "%40")],
    ["a leading space", ` ${GOOGLE_JWKS_URI}`],
    ["a trailing space", `${GOOGLE_JWKS_URI} `],
    ["a trailing newline", `${GOOGLE_JWKS_URI}\n`],
    ["a leading tab", `\t${GOOGLE_JWKS_URI}`],
    ["the development loopback URI", DEV_JWKS_URI],
    ...NOT_A_STRING_OR_TOO_LONG,
];

const DEVELOPMENT_JWKS_URI_VARIANTS: readonly (readonly [string, unknown])[] = [
    ["a non-loopback IPv4 host", "http://10.0.0.1:8791/jwks"],
    ["a non-loopback name", "http://sim.example.test:8791/jwks"],
    ["a loopback-prefixed name", "http://127.0.0.1.evil.test:8791/jwks"],
    ["a localhost-prefixed name", "http://localhost.evil.test:8791/jwks"],
    ["the production URI", GOOGLE_JWKS_URI],
    ["path /jwks/", "http://127.0.0.1:8791/jwks/"],
    ["path /JWKS", "http://127.0.0.1:8791/JWKS"],
    ["path /attacker/jwks", "http://127.0.0.1:8791/attacker/jwks"],
    ["path //jwks", "http://127.0.0.1:8791//jwks"],
    ["path /", "http://127.0.0.1:8791/"],
    ["no path", "http://127.0.0.1:8791"],
    ["http:// with an explicit :80", "http://127.0.0.1:80/jwks"],
    ["https:// with an explicit :443", "https://127.0.0.1:443/jwks"],
    ["a port with a leading zero", "http://127.0.0.1:08791/jwks"],
    ["host 127.1 (href differs)", "http://127.1:8791/jwks"],
    ["host 0x7f.1", "http://0x7f.1:8791/jwks"],
    ["host 2130706433", "http://2130706433:8791/jwks"],
    ["host [0:0:0:0:0:0:0:1]", "http://[0:0:0:0:0:0:0:1]:8791/jwks"],
    ["host LOCALHOST", "http://LOCALHOST:8791/jwks"],
    ["scheme HTTP:", "HTTP://127.0.0.1:8791/jwks"],
    ["dot segments", "http://127.0.0.1:8791/x/../jwks"],
    ["an empty query", "http://127.0.0.1:8791/jwks?"],
    ["a query", "http://127.0.0.1:8791/jwks?x=1"],
    ["an empty fragment", "http://127.0.0.1:8791/jwks#"],
    ["a fragment", "http://127.0.0.1:8791/jwks#x"],
    ["userinfo", "http://u:p@127.0.0.1:8791/jwks"],
    ["a username only", "http://u@127.0.0.1:8791/jwks"],
    ["a password only", "http://:p@127.0.0.1:8791/jwks"],
    ["scheme ftp:", "ftp://127.0.0.1:8791/jwks"],
    ["scheme ws:", "ws://127.0.0.1:8791/jwks"],
    ["scheme file:", "file://127.0.0.1/jwks"],
    ["not a URL", "/jwks"],
    ["a leading space", ` ${DEV_JWKS_URI}`],
    ["a trailing space", `${DEV_JWKS_URI} `],
    ...NOT_A_STRING_OR_TOO_LONG,
];

describe("parseTrustProfile pins a canonical jwks_uri (T-33 C3)", () => {
    it.each(PRODUCTION_JWKS_URI_VARIANTS)("production: rejects %s", (_name, jwksUri) => {
        const error = profileError({ ...productionJson(), jwks_uri: jwksUri });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
        expect(error.message).toBe("jwks_uri: INVALID_PROFILE");
    });

    it.each(DEVELOPMENT_JWKS_URI_VARIANTS)("development: rejects %s", (_name, jwksUri) => {
        const error = profileError({ ...developmentJson(), jwks_uri: jwksUri });
        expect([error.code, error.field]).toEqual(["INVALID_PROFILE", "jwks_uri"]);
        expect(error.message).toBe("jwks_uri: INVALID_PROFILE");
    });

    it("production: accepts exactly the F-07 constant", () => {
        expect(parseTrustProfile(productionJson()).jwks_uri).toBe(GOOGLE_JWKS_URI);
    });
});
