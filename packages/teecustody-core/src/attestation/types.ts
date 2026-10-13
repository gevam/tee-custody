// Attestation value types, errors and internal constructors (API.md §D, final).
import type { Bytes, Crypto, Fetcher } from "../capabilities.js";
import type { JsonObject } from "../json.js";

declare const parsedProfile: unique symbol;
declare const verified: unique symbol;

export type ProfileKind = "production" | "development";
export type SignerAlgorithm = "RSASSA_PSS_SHA256" | "RSASSA_PKCS1V15_SHA256" | "ECDSA_P256_SHA256"; // FACTS F-11
// key_id = signer fingerprint: lowercase hex SHA-256 of the signer's SPKI DER (F-11), ^[0-9a-f]{64}$, unique.
// algorithm = the one algorithm that signer uses. No public-key bytes in the profile.
export interface SignerKey {
    readonly key_id: string;
    readonly algorithm: SignerAlgorithm;
} // D-016

// spec §15.4 fields + [CI-4] additions, profile v2 (INC-2-API §16.1, D-043); only parseTrustProfile creates one
export interface TrustProfile {
    readonly [parsedProfile]: true;
    readonly profile_version: 2;
    readonly profile_kind: ProfileKind;
    readonly token_type: "OIDC";
    readonly issuer: string;
    readonly jwks_uri: string;
    readonly expected_audience: string;
    readonly token_max_age_s: number;
    readonly allowed_hwmodels: readonly string[];
    readonly allowed_digests: readonly string[];
    readonly signer_keys: readonly SignerKey[];
    readonly signers_required: number;
    readonly expected_args_hash: string;
    readonly expected_env_hash: string;
}

// [CI-9 amended] no digest input; INC-2 bundle verification binds pre-key digest to
// VerifiedAttestation.imageDigest
export interface ExpectedAttestation {
    readonly identityNonce: Bytes;
}

// only verifyAttestation creates one
export interface VerifiedAttestation {
    readonly [verified]: true;
    readonly issuer: string;
    readonly audience: string;
    readonly imageDigest: string;
    readonly signerKeyIds: readonly string[]; // sorted ascending
    readonly hwmodel: string;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
}

export type AttestationErrorCode =
    | "MALFORMED"
    | "UNTRUSTED_SIGNER"
    | "CLAIM_MISSING"
    | "CLAIM_MISMATCH"
    | "NOT_YET_VALID"
    | "EXPIRED"
    | "UNSUPPORTED_ALGORITHM";
export type AttestationCheckId =
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
    | "launch_config";
export class AttestationError extends Error {
    constructor(
        readonly code: AttestationErrorCode,
        readonly check: AttestationCheckId,
    ) {
        super(`${check}: ${code}`);
    }
}
export type TrustProfileErrorCode =
    "INVALID_PROFILE" | "UNSUPPORTED_TOKEN_TYPE" | "UNSUPPORTED_ALGORITHM";
export class TrustProfileError extends Error {
    constructor(
        readonly code: TrustProfileErrorCode,
        readonly field: string,
    ) {
        super(`${field}: ${code}`);
    }
}

export interface VerifierLimits {
    readonly maxTokenBytes: number;
    readonly maxDiscoveryBytes: number;
    readonly maxJwksBytes: number;
}

// [CI-1]
export interface VerifierDeps {
    readonly crypto: Pick<Crypto, "sha256" | "verifySignature">;
    readonly fetcher: Fetcher;
    readonly now: () => number; // Unix ms
    readonly limits: VerifierLimits;
}

export interface ParsedToken {
    readonly header: JsonObject;
    readonly claims: JsonObject;
    readonly signingInput: Bytes;
    readonly signature: Bytes;
}

// internal (not exported from index.ts):

const brandedProfiles = new WeakSet();

function deepFreeze<T extends object>(value: T): T {
    for (const child of Object.values(value)) {
        if (typeof child === "object" && child !== null) {
            deepFreeze(child as object);
        }
    }
    return Object.freeze(value);
}

// deep-freezes, registers in a module WeakSet
export function brandTrustProfile(p: Omit<TrustProfile, typeof parsedProfile>): TrustProfile {
    const profile = deepFreeze(p) as TrustProfile;
    brandedProfiles.add(profile);
    return profile;
}

export function isBrandedTrustProfile(p: unknown): p is TrustProfile {
    return typeof p === "object" && p !== null && brandedProfiles.has(p);
}

const verifiedAttestations = new WeakSet();

// frozen, registers in a module WeakSet (B-13)
export function createVerifiedAttestation(
    f: Omit<VerifiedAttestation, typeof verified>,
): VerifiedAttestation {
    const attestation = Object.freeze({
        ...f,
        signerKeyIds: Object.freeze([...f.signerKeyIds]),
    }) as VerifiedAttestation;
    verifiedAttestations.add(attestation);
    return attestation;
}

export function isVerifiedAttestation(v: unknown): v is VerifiedAttestation {
    return typeof v === "object" && v !== null && verifiedAttestations.has(v);
}
