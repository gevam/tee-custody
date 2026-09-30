// Frozen Core API surface (API.md §D): exact public names, stub owners, final wire types.
import { describe, expect, it } from "vitest";

import * as core from "../src/index.js";
import type {
    AttestationCheckId,
    AttestationErrorCode,
    Bytes,
    CanonicalEnvelope,
    CanonicalValue,
    CapabilityErrorCode,
    ClientId,
    ClientShare,
    Crypto,
    DecodeLimits,
    ExpectedAttestation,
    FetchResponse,
    Fetcher,
    HpkeReceiverContext,
    HpkeSenderContext,
    InstanceId,
    JsonObject,
    JsonValue,
    ParsedToken,
    ProfileKind,
    PublicKeyInput,
    PublishedBundle,
    PublishedResponse,
    RequestId,
    ResponseCursor,
    ResponsePage,
    RsaPublicJwk,
    SecurityEvent,
    SecurityEventCode,
    SecurityEventSink,
    ShareVault,
    SignatureAlgorithm,
    SignedPreKeyBundle,
    SignerAlgorithm,
    SignerKey,
    Transport,
    TrustProfile,
    TrustProfileErrorCode,
    VerifiedAttestation,
    VerifierDeps,
    VerifierLimits,
    WireErrorCode,
} from "../src/index.js";

// Compile-time half of criterion 6: every public type name in API.md §D resolves through index.ts.
export type PublicTypeSurface = [
    AttestationCheckId,
    AttestationErrorCode,
    Bytes,
    CanonicalEnvelope,
    CanonicalValue,
    CapabilityErrorCode,
    ClientId,
    ClientShare,
    Crypto,
    DecodeLimits,
    ExpectedAttestation,
    FetchResponse,
    Fetcher,
    HpkeReceiverContext,
    HpkeSenderContext,
    InstanceId,
    JsonObject,
    JsonValue,
    ParsedToken,
    ProfileKind,
    PublicKeyInput,
    PublishedBundle,
    PublishedResponse,
    RequestId,
    ResponseCursor,
    ResponsePage,
    RsaPublicJwk,
    SecurityEvent,
    SecurityEventCode,
    SecurityEventSink,
    ShareVault,
    SignatureAlgorithm,
    SignedPreKeyBundle,
    SignerAlgorithm,
    SignerKey,
    Transport,
    TrustProfile,
    TrustProfileErrorCode,
    VerifiedAttestation,
    VerifierDeps,
    VerifierLimits,
    WireErrorCode,
];

const PUBLIC_VALUES = [
    "AttestationError",
    "CapabilityError",
    "EncodingError",
    "PROTO",
    "TrustProfileError",
    "WireError",
    "base64Decode",
    "base64UrlDecode",
    "checkAudience",
    "checkImage",
    "checkIssuer",
    "checkLaunchConfig",
    "checkNonce",
    "checkPlatform",
    "checkSignature",
    "checkSupportAttributes",
    "checkTime",
    "decodeCanonical",
    "encodeCanonical",
    "encodeIdentityNonce",
    "getPath",
    "hexEncode",
    "identityNonceFromPublicKey",
    "isDebugMode",
    "isJsonObject",
    "launchConfigHash",
    "parseToken",
    "parseTrustProfile",
    "utf8DecodeStrict",
    "utf8Encode",
    "verifyAttestation",
];

const token = {} as ParsedToken;
const profile = {} as TrustProfile;
const deps = {} as VerifierDeps;
const sink = {} as SecurityEventSink;
const bytes = new Uint8Array(0);
const limits: DecodeLimits = { maxBytes: 1, maxDepth: 1, maxItems: 1 };

const STUBS: readonly (readonly [string, string, () => unknown])[] = [
    ["encodeCanonical", "T-09", () => core.encodeCanonical(null)],
    ["decodeCanonical", "T-09", () => core.decodeCanonical(bytes, limits)],
    ["parseToken", "T-10", () => core.parseToken("", 1)],
    ["parseTrustProfile", "T-10", () => core.parseTrustProfile({})],
    ["encodeIdentityNonce", "T-10", () => core.encodeIdentityNonce(bytes)],
    [
        "identityNonceFromPublicKey",
        "T-10",
        () => core.identityNonceFromPublicKey(deps.crypto, bytes),
    ],
    ["checkSignature", "T-11", () => core.checkSignature(token, profile, deps)],
    [
        "checkIssuer",
        "T-11",
        () => {
            core.checkIssuer(token, profile);
        },
    ],
    [
        "checkAudience",
        "T-12",
        () => {
            core.checkAudience(token, profile);
        },
    ],
    [
        "checkTime",
        "T-12",
        () => {
            core.checkTime(token, profile, 0);
        },
    ],
    [
        "checkNonce",
        "T-12",
        () => {
            core.checkNonce(token, { identityNonce: bytes });
        },
    ],
    [
        "checkPlatform",
        "T-12",
        () => {
            core.checkPlatform(token, profile);
        },
    ],
    ["isDebugMode", "T-12", () => core.isDebugMode(token)],
    [
        "checkSupportAttributes",
        "T-12",
        () => {
            core.checkSupportAttributes(token);
        },
    ],
    ["checkImage", "T-13", () => core.checkImage(token, profile)],
    ["launchConfigHash", "T-15", () => core.launchConfigHash([], deps.crypto)],
    ["checkLaunchConfig", "T-15", () => core.checkLaunchConfig(token, profile, deps)],
    [
        "verifyAttestation",
        "T-15",
        () => core.verifyAttestation("", profile, { identityNonce: bytes }, sink, deps),
    ],
];

describe("index.ts public surface", () => {
    it("exports exactly the API.md §D public values", () => {
        expect(Object.keys(core).sort()).toEqual([...PUBLIC_VALUES].sort());
    });

    it("does not export the internal attestation constructors", () => {
        for (const name of [
            "brandTrustProfile",
            "isBrandedTrustProfile",
            "createVerifiedAttestation",
        ]) {
            expect(Object.hasOwn(core, name)).toBe(false);
        }
    });
});

describe("stubs", () => {
    it.each(STUBS)("%s throws NOT_IMPLEMENTED: %s", async (_name, owner, call) => {
        await expect(Promise.resolve().then(call)).rejects.toThrow(
            new Error(`NOT_IMPLEMENTED: ${owner}`),
        );
    });
});

describe("wire/types.ts", () => {
    it("fixes the protocol string", () => {
        expect(core.PROTO).toBe("tee-chan-v1");
    });

    it("WireError message is exactly its code", () => {
        const error = new core.WireError("NONCANONICAL");
        expect(error).toBeInstanceOf(Error);
        expect(error.code).toBe("NONCANONICAL");
        expect(error.message).toBe("NONCANONICAL");
    });
});
