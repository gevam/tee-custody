// Frozen Core API surface (API.md §D): exact public names, stub owners, final wire types.
import { describe, expect, expectTypeOf, it } from "vitest";

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

// Compile-time pins (API.md §D): checked by `pnpm -r typecheck` (tsconfig.test.json includes test/**).
// Any added parameter, option, property, or changed return type fails type-checking.
type StringKeyed<T> = { [K in keyof T as K extends string ? K : never]: T[K] };
type BrandKey<T> = Exclude<keyof T, string>;

describe("API.md §D type pins", () => {
    it("pins the capability contracts", () => {
        expectTypeOf<Bytes>().toEqualTypeOf<Uint8Array>();
        expectTypeOf<InstanceId>().toEqualTypeOf<string>();
        expectTypeOf<ClientId>().toEqualTypeOf<string>();
        expectTypeOf<RequestId>().toEqualTypeOf<string>();
        expectTypeOf<ResponseCursor>().toEqualTypeOf<string>();
        expectTypeOf<SignedPreKeyBundle>().toEqualTypeOf<Uint8Array>();
        expectTypeOf<CanonicalEnvelope>().toEqualTypeOf<Uint8Array>();
        expectTypeOf<ClientShare>().toEqualTypeOf<Uint8Array>();
        expectTypeOf<CapabilityErrorCode>().toEqualTypeOf<
            | "INVALID_ARGUMENT"
            | "NOT_FOUND"
            | "UNAVAILABLE"
            | "INVALID_RESPONSE"
            | "UNSUPPORTED"
            | "USER_PRESENCE_REQUIRED"
            | "AUTHENTICATION_FAILED"
            | "HTTP_ERROR"
            | "UNSUPPORTED_ALGORITHM"
            | "INTERNAL"
        >();
        expectTypeOf(core.CapabilityError).constructorParameters.toEqualTypeOf<
            [CapabilityErrorCode]
        >();
        expectTypeOf<core.CapabilityError>().toExtend<Error>();
        expectTypeOf<Pick<core.CapabilityError, "code">>().toEqualTypeOf<{
            readonly code: CapabilityErrorCode;
        }>();
        expectTypeOf<PublishedBundle>().toEqualTypeOf<{
            readonly instanceId: string;
            readonly bundle: Uint8Array;
        }>();
        expectTypeOf<PublishedResponse>().toEqualTypeOf<{
            readonly requestId: string;
            readonly body: Uint8Array;
        }>();
        expectTypeOf<ResponsePage>().toEqualTypeOf<{
            readonly responses: readonly PublishedResponse[];
            readonly next: string | undefined;
        }>();
        expectTypeOf<Transport>().toEqualTypeOf<{
            listBundles(): Promise<readonly PublishedBundle[]>;
            postRequest(instance: string, body: Uint8Array): Promise<string>;
            getResponses(client: string, after?: string): Promise<ResponsePage>;
        }>();
        expectTypeOf<ShareVault>().toEqualTypeOf<{
            get(client: string): Promise<Uint8Array | undefined>;
            set(client: string, share: Uint8Array): Promise<void>;
            clear(client: string): Promise<void>;
        }>();
        expectTypeOf<FetchResponse>().toEqualTypeOf<{
            readonly status: number;
            readonly body: Uint8Array;
        }>();
        expectTypeOf<Fetcher>().toEqualTypeOf<{ get(url: string): Promise<FetchResponse> }>();
        expectTypeOf<HpkeSenderContext>().toEqualTypeOf<{
            readonly encapsulatedKey: Uint8Array;
            seal(aad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
            export(label: Uint8Array, length: number): Promise<Uint8Array>;
            destroy(): void;
        }>();
        expectTypeOf<HpkeReceiverContext>().toEqualTypeOf<{
            open(aad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
            export(label: Uint8Array, length: number): Promise<Uint8Array>;
            destroy(): void;
        }>();
        expectTypeOf<SignatureAlgorithm>().toEqualTypeOf<"RSASSA_PKCS1V15_SHA256">();
        expectTypeOf<RsaPublicJwk>().toEqualTypeOf<{
            readonly kty: "RSA";
            readonly n: string;
            readonly e: string;
        }>();
        expectTypeOf<PublicKeyInput>().toEqualTypeOf<{
            readonly format: "jwk";
            readonly jwk: RsaPublicJwk;
        }>();
        expectTypeOf<SecurityEventCode>().toEqualTypeOf<"ATTESTATION_DEBUG_MODE">();
        expectTypeOf<SecurityEvent>().toEqualTypeOf<{
            readonly code: "ATTESTATION_DEBUG_MODE";
            readonly at: number;
        }>();
        expectTypeOf<SecurityEventSink>().toEqualTypeOf<{
            report(event: SecurityEvent): Promise<void>;
        }>();
        expectTypeOf<Crypto>().toEqualTypeOf<{
            randomBytes(length: number): Uint8Array;
            sha256(data: Uint8Array): Promise<Uint8Array>;
            verifyEd25519(
                publicKey: Uint8Array,
                data: Uint8Array,
                signature: Uint8Array,
            ): Promise<boolean>;
            verifySignature(
                algorithm: "RSASSA_PKCS1V15_SHA256",
                key: PublicKeyInput,
                data: Uint8Array,
                signature: Uint8Array,
            ): Promise<boolean>;
            setupHpkeSender(
                recipientPublicKey: Uint8Array,
                info: Uint8Array,
            ): Promise<HpkeSenderContext>;
            setupHpkeReceiver(
                recipientPrivateKey: Uint8Array,
                encapsulatedKey: Uint8Array,
                info: Uint8Array,
            ): Promise<HpkeReceiverContext>;
            aes256GcmEncrypt(
                key: Uint8Array,
                nonce: Uint8Array,
                aad: Uint8Array,
                plaintext: Uint8Array,
            ): Promise<Uint8Array>;
            aes256GcmDecrypt(
                key: Uint8Array,
                nonce: Uint8Array,
                aad: Uint8Array,
                ciphertext: Uint8Array,
            ): Promise<Uint8Array>;
        }>();
    });

    it("pins encoding.ts and json.ts", () => {
        expectTypeOf(core.EncodingError).toBeConstructibleWith("message");
        expectTypeOf<core.EncodingError>().toEqualTypeOf<Error>();
        expectTypeOf(core.base64UrlDecode).toEqualTypeOf<(s: string) => Uint8Array>();
        expectTypeOf(core.base64Decode).toEqualTypeOf<(s: string) => Uint8Array>();
        expectTypeOf(core.hexEncode).toEqualTypeOf<(b: Uint8Array) => string>();
        expectTypeOf(core.utf8Encode).toEqualTypeOf<(s: string) => Uint8Array>();
        expectTypeOf(core.utf8DecodeStrict).toEqualTypeOf<(b: Uint8Array) => string>();
        expectTypeOf<JsonValue>().toEqualTypeOf<
            null | boolean | number | string | readonly JsonValue[] | JsonObject
        >();
        expectTypeOf<JsonObject>().toEqualTypeOf<{ readonly [key: string]: JsonValue }>();
        expectTypeOf(core.isJsonObject).toEqualTypeOf<
            (v: JsonValue | undefined) => v is JsonObject
        >();
        expectTypeOf(core.getPath).toEqualTypeOf<
            (root: JsonObject, path: readonly string[]) => JsonValue | undefined
        >();
    });

    it("pins wire/types.ts and wire/cbor.ts", () => {
        expectTypeOf<typeof core.PROTO>().toEqualTypeOf<"tee-chan-v1">();
        expectTypeOf<CanonicalValue>().toEqualTypeOf<
            | null
            | boolean
            | number
            | bigint
            | string
            | Uint8Array
            | readonly CanonicalValue[]
            | ReadonlyMap<string, CanonicalValue>
        >();
        expectTypeOf<DecodeLimits>().toEqualTypeOf<{
            readonly maxBytes: number;
            readonly maxDepth: number;
            readonly maxItems: number;
        }>();
        expectTypeOf<WireErrorCode>().toEqualTypeOf<
            "TOO_LARGE" | "MALFORMED" | "NONCANONICAL" | "UNSUPPORTED_TYPE" | "LIMIT_EXCEEDED"
        >();
        expectTypeOf(core.WireError).constructorParameters.toEqualTypeOf<[WireErrorCode]>();
        expectTypeOf<Pick<core.WireError, "code">>().toEqualTypeOf<{
            readonly code: WireErrorCode;
        }>();
        expectTypeOf(core.encodeCanonical).toEqualTypeOf<(value: CanonicalValue) => Uint8Array>();
        expectTypeOf(core.decodeCanonical).toEqualTypeOf<
            (data: Uint8Array, limits: DecodeLimits) => CanonicalValue
        >();
    });

    it("pins attestation/types.ts", () => {
        expectTypeOf<ProfileKind>().toEqualTypeOf<"production" | "development">();
        expectTypeOf<SignerAlgorithm>().toEqualTypeOf<
            "RSASSA_PSS_SHA256" | "RSASSA_PKCS1V15_SHA256" | "ECDSA_P256_SHA256"
        >();
        expectTypeOf<SignerKey>().toEqualTypeOf<{
            readonly key_id: string;
            readonly algorithm: SignerAlgorithm;
        }>();
        expectTypeOf<StringKeyed<TrustProfile>>().toEqualTypeOf<{
            readonly profile_version: 1;
            readonly profile_kind: ProfileKind;
            readonly token_type: "OIDC";
            readonly issuer: string;
            readonly discovery_url: string;
            readonly jwks_origin: string;
            readonly expected_audience: string;
            readonly token_max_age_s: number;
            readonly allowed_hwmodels: readonly string[];
            readonly allowed_digests: readonly string[];
            readonly signer_keys: readonly SignerKey[];
            readonly signers_required: number;
            readonly expected_args_hash: string;
            readonly expected_env_hash: string;
        }>();
        expectTypeOf<BrandKey<TrustProfile>>().toExtend<symbol>();
        expectTypeOf<TrustProfile[BrandKey<TrustProfile>]>().toEqualTypeOf<true>();
        expectTypeOf<StringKeyed<TrustProfile>>().not.toExtend<TrustProfile>();
        expectTypeOf<ExpectedAttestation>().toEqualTypeOf<{
            readonly identityNonce: Uint8Array;
        }>();
        expectTypeOf<StringKeyed<VerifiedAttestation>>().toEqualTypeOf<{
            readonly issuer: string;
            readonly audience: string;
            readonly imageDigest: string;
            readonly signerKeyIds: readonly string[];
            readonly hwmodel: string;
            readonly issuedAtMs: number;
            readonly expiresAtMs: number;
        }>();
        expectTypeOf<BrandKey<VerifiedAttestation>>().toExtend<symbol>();
        expectTypeOf<VerifiedAttestation[BrandKey<VerifiedAttestation>]>().toEqualTypeOf<true>();
        expectTypeOf<StringKeyed<VerifiedAttestation>>().not.toExtend<VerifiedAttestation>();
        expectTypeOf<AttestationErrorCode>().toEqualTypeOf<
            | "MALFORMED"
            | "UNTRUSTED_SIGNER"
            | "CLAIM_MISSING"
            | "CLAIM_MISMATCH"
            | "NOT_YET_VALID"
            | "EXPIRED"
            | "UNSUPPORTED_ALGORITHM"
        >();
        expectTypeOf<AttestationCheckId>().toEqualTypeOf<
            | "profile"
            | "token"
            | "signature"
            | "issuer"
            | "audience"
            | "time"
            | "nonce"
            | "platform"
            | "support_attributes"
            | "image"
            | "launch_config"
        >();
        expectTypeOf(core.AttestationError).constructorParameters.toEqualTypeOf<
            [AttestationErrorCode, AttestationCheckId]
        >();
        expectTypeOf<Pick<core.AttestationError, "code" | "check">>().toEqualTypeOf<{
            readonly code: AttestationErrorCode;
            readonly check: AttestationCheckId;
        }>();
        expectTypeOf<core.AttestationError>().toExtend<Error>();
        expectTypeOf<TrustProfileErrorCode>().toEqualTypeOf<
            "INVALID_PROFILE" | "UNSUPPORTED_TOKEN_TYPE" | "UNSUPPORTED_ALGORITHM"
        >();
        expectTypeOf(core.TrustProfileError).constructorParameters.toEqualTypeOf<
            [TrustProfileErrorCode, string]
        >();
        expectTypeOf<Pick<core.TrustProfileError, "code" | "field">>().toEqualTypeOf<{
            readonly code: TrustProfileErrorCode;
            readonly field: string;
        }>();
        expectTypeOf<core.TrustProfileError>().toExtend<Error>();
        expectTypeOf<VerifierLimits>().toEqualTypeOf<{
            readonly maxTokenBytes: number;
            readonly maxDiscoveryBytes: number;
            readonly maxJwksBytes: number;
        }>();
        expectTypeOf<VerifierDeps>().toEqualTypeOf<{
            readonly crypto: Pick<Crypto, "sha256" | "verifySignature">;
            readonly fetcher: Fetcher;
            readonly now: () => number;
            readonly limits: VerifierLimits;
        }>();
        expectTypeOf<ParsedToken>().toEqualTypeOf<{
            readonly header: JsonObject;
            readonly claims: JsonObject;
            readonly signingInput: Uint8Array;
            readonly signature: Uint8Array;
        }>();
    });

    it("pins the stub signatures", () => {
        expectTypeOf(core.parseToken).toEqualTypeOf<
            (token: string, maxTokenBytes: number) => ParsedToken
        >();
        expectTypeOf(core.parseTrustProfile).toEqualTypeOf<(input: unknown) => TrustProfile>();
        expectTypeOf(core.encodeIdentityNonce).toEqualTypeOf<
            (identityNonce: Uint8Array) => string
        >();
        expectTypeOf(core.identityNonceFromPublicKey).toEqualTypeOf<
            (crypto: Pick<Crypto, "sha256">, identityPublicKey: Uint8Array) => Promise<Uint8Array>
        >();
        expectTypeOf(core.checkSignature).toEqualTypeOf<
            (t: ParsedToken, p: TrustProfile, deps: VerifierDeps) => Promise<void>
        >();
        expectTypeOf(core.checkIssuer).toEqualTypeOf<(t: ParsedToken, p: TrustProfile) => void>();
        expectTypeOf(core.checkAudience).toEqualTypeOf<(t: ParsedToken, p: TrustProfile) => void>();
        expectTypeOf(core.checkTime).toEqualTypeOf<
            (t: ParsedToken, p: TrustProfile, nowMs: number) => void
        >();
        expectTypeOf(core.checkNonce).toEqualTypeOf<
            (t: ParsedToken, e: ExpectedAttestation) => void
        >();
        expectTypeOf(core.checkPlatform).toEqualTypeOf<(t: ParsedToken, p: TrustProfile) => void>();
        expectTypeOf(core.isDebugMode).toEqualTypeOf<(t: ParsedToken) => boolean>();
        expectTypeOf(core.checkSupportAttributes).toEqualTypeOf<(t: ParsedToken) => void>();
        expectTypeOf(core.checkImage).toEqualTypeOf<
            (t: ParsedToken, p: TrustProfile) => readonly string[]
        >();
        expectTypeOf(core.launchConfigHash).toEqualTypeOf<
            (
                v: readonly string[] | ReadonlyMap<string, string>,
                crypto: Pick<Crypto, "sha256">,
            ) => Promise<string>
        >();
        expectTypeOf(core.checkLaunchConfig).toEqualTypeOf<
            (t: ParsedToken, p: TrustProfile, deps: VerifierDeps) => Promise<void>
        >();
        expectTypeOf(core.verifyAttestation).toEqualTypeOf<
            (
                token: string,
                profile: TrustProfile,
                expected: ExpectedAttestation,
                events: SecurityEventSink,
                deps: VerifierDeps,
            ) => Promise<VerifiedAttestation>
        >();
    });
});
