// Frozen Core API surface (API.md §D): exact public names, final wire types.
import { describe, expect, expectTypeOf, it } from "vitest";

import * as core from "../src/index.js";
import type {
    AttestationCheckId,
    AttestationErrorCode,
    BundleDeps,
    BundleErrorCode,
    BundleLimits,
    Bytes,
    CanonicalEnvelope,
    CanonicalValue,
    CapabilityErrorCode,
    ChannelClientConfig,
    ChannelErrorCode,
    ChannelLimits,
    ClientId,
    ClientShare,
    Clock,
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
    OpenOutcome,
    OpenPayload,
    ParsedToken,
    ProfileKind,
    PublicKeyInput,
    PublishedBundle,
    PublishedResponse,
    RemoteErrorCode,
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
    VerifiedBundle,
    VerifiedPreKey,
    VerifierDeps,
    VerifierLimits,
    WireErrorCode,
} from "../src/index.js";

const PUBLIC_VALUES = [
    "AttestationError",
    "BundleError",
    "CapabilityError",
    "ChannelClient",
    "ChannelError",
    "DEFAULT_CHANNEL_LIMITS",
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
    "prekeySigningMessage",
    "selectPreKey",
    "Session",
    "utf8DecodeStrict",
    "utf8Encode",
    "verifyAttestation",
    "verifyBundle",
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

    it.each([
        "isVerifiedAttestation",
        "isVerifiedBundle",
        "createVerifiedBundle",
        "openT2cFrame",
        "readOpenResult",
        "readFrameResult",
        "decodeResponse",
        "hpkeInfo",
    ])("does not export the internal channel name %s (API-TL §3)", (name) => {
        expect(Object.hasOwn(core, name)).toBe(false);
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

describe("INC-2-API §7 type pins", () => {
    it("pins bundle/types.ts, bundle/verify.ts and bundle/select.ts (§7.2)", () => {
        expectTypeOf<VerifiedPreKey>().toEqualTypeOf<{
            readonly id: number;
            readonly publicKey: Uint8Array;
            readonly notAfterMs: number;
        }>();
        expectTypeOf<StringKeyed<VerifiedBundle>>().toEqualTypeOf<{
            readonly instanceId: string;
            readonly identityPublicKey: Uint8Array;
            readonly attestation: VerifiedAttestation;
            readonly prekeys: readonly VerifiedPreKey[];
            readonly verifiedAtMs: number;
        }>();
        expectTypeOf<BrandKey<VerifiedBundle>>().toExtend<symbol>();
        expectTypeOf<VerifiedBundle[BrandKey<VerifiedBundle>]>().toEqualTypeOf<true>();
        expectTypeOf<StringKeyed<VerifiedBundle>>().not.toExtend<VerifiedBundle>();
        expectTypeOf<BundleErrorCode>().toEqualTypeOf<
            | "MALFORMED"
            | "ATTESTATION_FAILED"
            | "INSTANCE_MISMATCH"
            | "PREKEY_SIGNATURE_INVALID"
            | "NO_USABLE_PREKEY"
            | "UNSUPPORTED"
        >();
        expectTypeOf(core.BundleError).constructorParameters.toEqualTypeOf<
            [BundleErrorCode, (AttestationCheckId | undefined)?]
        >();
        expectTypeOf<core.BundleError>().toExtend<Error>();
        expectTypeOf<Pick<core.BundleError, "code" | "attestationCheck">>().toEqualTypeOf<{
            readonly code: BundleErrorCode;
            readonly attestationCheck?: AttestationCheckId | undefined;
        }>();
        expectTypeOf<BundleLimits>().toEqualTypeOf<{
            readonly decode: DecodeLimits;
            readonly maxPrekeys: number;
        }>();
        expectTypeOf<BundleDeps>().toEqualTypeOf<{
            readonly crypto: Pick<Crypto, "sha256" | "verifySignature" | "verifyEd25519">;
            readonly fetcher: Fetcher;
            readonly now: () => number;
            readonly verifierLimits: VerifierLimits;
            readonly bundleLimits: BundleLimits;
        }>();
        expectTypeOf(core.verifyBundle).toEqualTypeOf<
            (
                published: PublishedBundle,
                profile: TrustProfile,
                events: SecurityEventSink,
                deps: BundleDeps,
            ) => Promise<VerifiedBundle>
        >();
        expectTypeOf(core.prekeySigningMessage).toEqualTypeOf<
            (
                crypto: Pick<Crypto, "sha256">,
                instanceId: string,
                id: number,
                pub: Uint8Array,
                notAfter: number,
                imageDigest: string,
            ) => Promise<Uint8Array>
        >();
        expectTypeOf(core.selectPreKey).toEqualTypeOf<
            (
                bundle: VerifiedBundle,
                used: ReadonlySet<number>,
                nowMs: number,
                crypto: Pick<Crypto, "randomBytes">,
            ) => VerifiedPreKey | undefined
        >();
    });

    it("pins channel/types.ts, client.ts and session.ts (§7.4)", () => {
        expectTypeOf<Clock>().toEqualTypeOf<{
            now(): number;
            sleep(ms: number): Promise<void>;
        }>();
        expectTypeOf<ChannelLimits>().toEqualTypeOf<{
            readonly maxBundles: number;
            readonly bundle: BundleLimits;
            readonly verifier: VerifierLimits;
            readonly envelopeDecode: DecodeLimits;
            readonly aadDecode: DecodeLimits;
            readonly payloadDecode: DecodeLimits;
            readonly maxPayloadBytes: number;
            readonly responseTimeoutMs: number;
            readonly pollIntervalMs: number;
            readonly maxInFlight: number;
            readonly bundleMaxAgeMs: number;
        }>();
        expectTypeOf(core.DEFAULT_CHANNEL_LIMITS).toEqualTypeOf<ChannelLimits>();
        expectTypeOf<ChannelClientConfig>().toEqualTypeOf<{
            readonly trustProfile: TrustProfile;
            readonly transport: Transport;
            readonly crypto: Crypto;
            readonly fetcher: Fetcher;
            readonly securityEvents: SecurityEventSink;
            readonly clock: Clock;
            readonly limits?: ChannelLimits;
        }>();
        expectTypeOf<OpenPayload>().toEqualTypeOf<
            | {
                  readonly op: "open_session";
                  readonly clientId: string;
                  readonly cs: Uint8Array;
                  readonly keyId: Uint8Array;
                  readonly epoch: number;
              }
            | { readonly op: "enroll" }
        >();
        expectTypeOf<OpenOutcome>().toEqualTypeOf<{
            readonly session: core.Session;
            readonly payload: CanonicalValue;
        }>();
        expectTypeOf(core.ChannelClient).constructorParameters.toEqualTypeOf<
            [ChannelClientConfig]
        >();
        expectTypeOf<core.ChannelClient>().toEqualTypeOf<{
            fetchVerifiedBundles(): Promise<readonly VerifiedBundle[]>;
            open(payload: OpenPayload, bundle?: VerifiedBundle): Promise<OpenOutcome>;
        }>();
        expectTypeOf<core.Session>().toEqualTypeOf<{
            readonly sessionId: Uint8Array;
            readonly instanceId: string;
            readonly clientId: string;
            readonly closed: boolean;
            request(op: string, payload: CanonicalValue): Promise<CanonicalValue>;
            close(): Promise<void>;
        }>();
    });

    it("pins channel/errors.ts (§7.5)", () => {
        expectTypeOf<ChannelErrorCode>().toEqualTypeOf<
            | "NO_VERIFIED_BUNDLE"
            | "UNVERIFIED_BUNDLE"
            | "NO_USABLE_PREKEY"
            | "TRANSPORT"
            | "TIMEOUT"
            | "INVALID_RESPONSE"
            | "REMOTE_ERROR"
            | "SESSION_CLOSED"
            | "SEQUENCE_EXHAUSTED"
            | "INVALID_ARGUMENT"
            | "CRYPTO_UNAVAILABLE"
        >();
        expectTypeOf<RemoteErrorCode>().toEqualTypeOf<
            | "INVALID_FRAME"
            | "AUTHENTICATION_FAILED"
            | "REPLAYED_OR_OUT_OF_ORDER"
            | "UNKNOWN_CLIENT"
            | "UNKNOWN_OPERATION"
            | "NOT_AUTHORIZED"
            | "LIMIT_EXCEEDED"
            | "RECORD_NOT_FOUND"
            | "BACKEND_UNAVAILABLE"
            | "INTERNAL"
            | "UNKNOWN"
        >();
        expectTypeOf(core.ChannelError).constructorParameters.toEqualTypeOf<
            [ChannelErrorCode, (CapabilityErrorCode | RemoteErrorCode | undefined)?]
        >();
        expectTypeOf<core.ChannelError>().toExtend<Error>();
        expectTypeOf<Pick<core.ChannelError, "code" | "detail">>().toEqualTypeOf<{
            readonly code: ChannelErrorCode;
            readonly detail?: CapabilityErrorCode | RemoteErrorCode | undefined;
        }>();
    });
});

describe("DEFAULT_CHANNEL_LIMITS (INC-2-API §7.4)", () => {
    it("equals the §7.4 values", () => {
        expect(core.DEFAULT_CHANNEL_LIMITS).toStrictEqual({
            maxBundles: 16,
            bundle: { decode: { maxBytes: 65_536, maxDepth: 4, maxItems: 4096 }, maxPrekeys: 256 },
            verifier: { maxTokenBytes: 16_384, maxDiscoveryBytes: 65_536, maxJwksBytes: 65_536 },
            envelopeDecode: { maxBytes: 65_536, maxDepth: 2, maxItems: 16 },
            aadDecode: { maxBytes: 512, maxDepth: 2, maxItems: 16 },
            payloadDecode: { maxBytes: 32_768, maxDepth: 16, maxItems: 4096 },
            maxPayloadBytes: 32_768,
            responseTimeoutMs: 30_000,
            pollIntervalMs: 500,
            maxInFlight: 8,
            bundleMaxAgeMs: 60_000,
        });
    });

    it("is frozen at every level", () => {
        const limits = core.DEFAULT_CHANNEL_LIMITS;
        for (const value of [
            limits,
            limits.bundle,
            limits.bundle.decode,
            limits.verifier,
            limits.envelopeDecode,
            limits.aadDecode,
            limits.payloadDecode,
        ]) {
            expect(Object.isFrozen(value)).toBe(true);
        }
    });
});
