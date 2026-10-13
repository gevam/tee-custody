// Channel error types (INC-2-API §7.5; API-TL §3). Final. Every error carries only codes; message === code.
import type { CapabilityErrorCode } from "../capabilities.js";

export type ChannelErrorCode =
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
    | "CRYPTO_UNAVAILABLE";

// any other wire error-code maps to "UNKNOWN"
export type RemoteErrorCode =
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
    | "UNKNOWN";

// detail: TRANSPORT / CRYPTO_UNAVAILABLE / REMOTE_ERROR only
export class ChannelError extends Error {
    constructor(
        readonly code: ChannelErrorCode,
        readonly detail?: CapabilityErrorCode | RemoteErrorCode,
    ) {
        super(code);
    }
}

// internal (not exported from index.ts)
export type FrameRejectCode = "INVALID_ENVELOPE" | "SEQ_REJECTED" | "AUTH_FAILED";

export class FrameReject extends Error {
    constructor(readonly code: FrameRejectCode) {
        super(code);
    }
}
