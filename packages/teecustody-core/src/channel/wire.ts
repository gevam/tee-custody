// Channel wire codec (INC-2-API §7.3, §3.1; API-TL §3). Constants and types final; functions stub → T-15.
// Every function goes through encodeCanonical/decodeCanonical only. The nonce builder is not here (R-5).
import type { Bytes, CanonicalEnvelope, ClientId, Crypto, InstanceId } from "../capabilities.js";
import { encodeCanonical } from "../wire/cbor.js";
import { PROTO, type CanonicalValue, type DecodeLimits } from "../wire/types.js";
import type { OpenPayload } from "./types.js";

export const MAX_SEQ = 9_007_199_254_740_991; // also MAX_UNIX_S
export const MAX_UNIX_S = 9_007_199_254_740_991;
export const HEX32_PATTERN = /^[0-9a-f]{32}$/;
export const OP_NAME_PATTERN = /^[a-z][a-z0-9_.]{0,63}$/;
export const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

export interface OpenAadFields {
    readonly clientId: ClientId;
    readonly instanceId: InstanceId;
    readonly prekeyId: number;
    readonly requestId: Bytes;
    readonly timestamp: number;
}

export interface FrameAadFields {
    readonly sessionId: Bytes;
    readonly seq: number;
    readonly op: string;
}

// seq is 0
export interface OpenResultAadFields {
    readonly sessionId: Bytes | null;
    readonly requestId: Bytes;
}

export interface OpenResultEnvelope {
    readonly kind: "open_result";
    readonly aadBytes: Bytes;
    readonly aad: OpenResultAadFields;
    readonly ct: Bytes;
}

export interface FrameResultEnvelope {
    readonly kind: "frame_result";
    readonly aadBytes: Bytes;
    readonly aad: FrameAadFields;
    readonly ct: Bytes;
}

export type OpenResultBody =
    | { readonly ok: true; readonly payload: CanonicalValue }
    | { readonly ok: false; readonly error: string };

export type FrameResultBody =
    | { readonly re: number; readonly ok: true; readonly payload: CanonicalValue }
    | { readonly re: number; readonly ok: false; readonly error: string };

function encodeMap(entries: Record<string, CanonicalValue>): Bytes {
    return encodeCanonical(new Map(Object.entries(entries)));
}

// RangeError("<FIELD>_RANGE")
export function encodeOpenAad(aad: OpenAadFields): Bytes {
    return encodeMap({
        proto: PROTO,
        client_id: aad.clientId,
        instance_id: aad.instanceId,
        prekey_id: aad.prekeyId,
        request_id: aad.requestId,
        timestamp: aad.timestamp,
    });
}

// RangeError: cs ≠ 32, keyId ≠ 16, epoch ∉ uint32
export function encodeOpenPlaintext(payload: OpenPayload): Bytes {
    if (payload.op === "enroll") {
        return encodeMap({ op: "enroll" });
    }
    return encodeMap({
        op: "open_session",
        cs: payload.cs,
        key_id: payload.keyId,
        epoch: payload.epoch,
    });
}

export function encodeOpenRequest(aadBytes: Bytes, enc: Bytes, ct: Bytes): CanonicalEnvelope {
    return encodeMap({ kind: "open", aad: aadBytes, enc, ct });
}

// RangeError("SEQ_RANGE"|"OP_RANGE"|"SESSION_ID_RANGE")
export function encodeFrameAad(aad: FrameAadFields): Bytes {
    return encodeMap({ session_id: aad.sessionId, seq: aad.seq, op: aad.op });
}

export function encodeFrameRequest(aadBytes: Bytes, ct: Bytes): CanonicalEnvelope {
    return encodeMap({ kind: "frame", aad: aadBytes, ct });
}

// WireError from the codec; WireError("MALFORMED") on any schema failure
export function decodeResponse(
    body: Bytes,
    envelopeDecode: DecodeLimits,
    aadDecode: DecodeLimits,
): OpenResultEnvelope | FrameResultEnvelope {
    throw new Error("NOT_IMPLEMENTED: T-15");
}

// ChannelError("INVALID_RESPONSE") on any failure, incl. R-3
export function decodeOpenResultPlaintext(
    pt: Bytes,
    aad: OpenResultAadFields,
    limits: DecodeLimits,
): OpenResultBody {
    throw new Error("NOT_IMPLEMENTED: T-15");
}

// ChannelError("INVALID_RESPONSE")
export function decodeFrameResultPlaintext(pt: Bytes, limits: DecodeLimits): FrameResultBody {
    throw new Error("NOT_IMPLEMENTED: T-15");
}

// 47 B; RangeError
export function hpkeInfo(
    crypto: Pick<Crypto, "sha256">,
    ikPub: Bytes,
    prekeyId: number,
): Promise<Bytes> {
    throw new Error("NOT_IMPLEMENTED: T-15");
}
