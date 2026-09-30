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
