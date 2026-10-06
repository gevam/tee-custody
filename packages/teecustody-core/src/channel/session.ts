// Client session and decrypt-side frame helpers (INC-2-API §7.4; API-TL §3; D2-16). Stub → T-26.
// None of the helpers seals. The nonce builder is module-private to this file (R-5).
import type { Bytes, ClientId, Crypto, InstanceId } from "../capabilities.js";
import type { CanonicalValue } from "../wire/types.js";
import type { RemoteErrorCode } from "./errors.js";
import type { ChannelLimits } from "./types.js";
import type { FrameAadFields } from "./wire.js";

// Placeholder; T-26 replaces it (API-TL §3).
export type SessionInit = Readonly<Record<string, never>>;

// constructed only by ChannelClient
export class Session {
    readonly sessionId: Bytes;
    readonly instanceId: InstanceId;
    readonly clientId: ClientId;

    // TypeError("INVALID_CONFIG") unless token is the module-private symbol of session.ts
    constructor(token: symbol, init: SessionInit) {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }

    get closed(): boolean {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }

    request(op: string, payload: CanonicalValue): Promise<CanonicalValue> {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }

    // sends op "close"; idempotent; destroys keys even on failure
    close(): Promise<void> {
        throw new Error("NOT_IMPLEMENTED: T-26");
    }
}

export interface OpenedFrame {
    readonly aad: FrameAadFields;
    readonly plaintext: Bytes;
}

// decode failure or kind ≠ "frame_result" → FrameReject("INVALID_ENVELOPE"); aad.seq <= lastSeq →
// FrameReject("SEQ_REJECTED") before decrypting; AEAD failure → FrameReject("AUTH_FAILED"). lastSeq -1 = none.
export function openT2cFrame(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    key: Bytes,
    lastSeq: number,
    envelope: Bytes,
    limits: Pick<ChannelLimits, "envelopeDecode" | "aadDecode">,
): Promise<OpenedFrame> {
    throw new Error("NOT_IMPLEMENTED: T-26");
}

export type OpenResultMatch =
    | { readonly ok: true; readonly sessionId: Bytes; readonly payload: CanonicalValue }
    | { readonly ok: false; readonly error: RemoteErrorCode };

// undefined (ignore): decode failure, kind ≠ "open_result", aad.requestId ≠ requestId, AEAD failure.
// ChannelError("INVALID_RESPONSE"): AEAD passed but plaintext violates the schema or R-3.
export function readOpenResult(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    keyT2c: Bytes,
    requestId: Bytes,
    envelope: Bytes,
    limits: ChannelLimits,
): Promise<OpenResultMatch | undefined> {
    throw new Error("NOT_IMPLEMENTED: T-26");
}

export type FrameResultMatch =
    | {
          readonly seq: number;
          readonly op: string;
          readonly re: number;
          readonly ok: true;
          readonly payload: CanonicalValue;
      }
    | {
          readonly seq: number;
          readonly op: string;
          readonly re: number;
          readonly ok: false;
          readonly error: RemoteErrorCode;
      };

// undefined: decode failure, kind ≠ "frame_result", session mismatch, aad.seq <= lastSeq, AEAD failure,
// or plaintext re ≠ re. ChannelError("INVALID_RESPONSE"): AEAD passed but the plaintext violates the schema.
// Wire error codes outside RemoteErrorCode map to "UNKNOWN" (INC-2-API §7.5).
export function readFrameResult(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    keyT2c: Bytes,
    sessionId: Bytes,
    re: number,
    lastSeq: number,
    envelope: Bytes,
    limits: ChannelLimits,
): Promise<FrameResultMatch | undefined> {
    throw new Error("NOT_IMPLEMENTED: T-26");
}
