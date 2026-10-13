// Channel wire codec (INC-2-API §7.3, §3.1; API-TL §3). Constants and types final; functions stub → T-15.
// Every function goes through encodeCanonical/decodeCanonical only. The nonce builder is not here (R-5).
import type { Bytes, CanonicalEnvelope, ClientId, Crypto, InstanceId } from "../capabilities.js";
import { decodeCanonical, encodeCanonical } from "../wire/cbor.js";
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

const MAX_UINT32 = 0xffff_ffff;
const ID_BYTES = 16;
const KEY_BYTES = 32;
const MIN_CT = 16;
const MAX_OPEN_CT = 2048;
const MAX_CT = 32_784;

type RangeCode =
    | "CLIENT_ID_RANGE"
    | "INSTANCE_ID_RANGE"
    | "PREKEY_ID_RANGE"
    | "REQUEST_ID_RANGE"
    | "TIMESTAMP_RANGE"
    | "SESSION_ID_RANGE"
    | "SEQ_RANGE"
    | "OP_RANGE"
    | "ENC_RANGE"
    | "CT_RANGE"
    | "IK_PUB_RANGE"
    | "CS_RANGE"
    | "KEY_ID_RANGE"
    | "EPOCH_RANGE";

// The arguments are typed, but every check also holds for a value the type system was bypassed for.
function check(ok: boolean, code: RangeCode): void {
    if (!ok) {
        throw new RangeError(code);
    }
}

function isUint(value: unknown, max: number): boolean {
    return (
        typeof value === "number" &&
        Number.isSafeInteger(value) &&
        !Object.is(value, -0) &&
        value >= 0 &&
        value <= max
    );
}

function matches(value: unknown, pattern: RegExp): boolean {
    return typeof value === "string" && pattern.test(value);
}

function hasLength(value: unknown, min: number, max = min): boolean {
    return value instanceof Uint8Array && value.length >= min && value.length <= max;
}

function encodeMap(entries: Record<string, CanonicalValue>): Bytes {
    return encodeCanonical(new Map(Object.entries(entries)));
}

// RangeError("<FIELD>_RANGE")
export function encodeOpenAad(aad: OpenAadFields): Bytes {
    check(matches(aad.clientId, HEX32_PATTERN), "CLIENT_ID_RANGE");
    check(matches(aad.instanceId, HEX32_PATTERN), "INSTANCE_ID_RANGE");
    check(isUint(aad.prekeyId, MAX_UINT32), "PREKEY_ID_RANGE");
    check(hasLength(aad.requestId, ID_BYTES), "REQUEST_ID_RANGE");
    check(isUint(aad.timestamp, MAX_UNIX_S), "TIMESTAMP_RANGE");
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
    check(hasLength(payload.cs, KEY_BYTES), "CS_RANGE");
    check(hasLength(payload.keyId, ID_BYTES), "KEY_ID_RANGE");
    check(isUint(payload.epoch, MAX_UINT32), "EPOCH_RANGE");
    return encodeMap({
        op: "open_session",
        cs: payload.cs,
        key_id: payload.keyId,
        epoch: payload.epoch,
    });
}

export function encodeOpenRequest(aadBytes: Bytes, enc: Bytes, ct: Bytes): CanonicalEnvelope {
    check(hasLength(enc, KEY_BYTES), "ENC_RANGE");
    check(hasLength(ct, MIN_CT, MAX_OPEN_CT), "CT_RANGE");
    return encodeMap({ kind: "open", aad: aadBytes, enc, ct });
}

// RangeError("SEQ_RANGE"|"OP_RANGE"|"SESSION_ID_RANGE")
export function encodeFrameAad(aad: FrameAadFields): Bytes {
    check(hasLength(aad.sessionId, ID_BYTES), "SESSION_ID_RANGE");
    check(isUint(aad.seq, MAX_SEQ), "SEQ_RANGE");
    check(matches(aad.op, OP_NAME_PATTERN), "OP_RANGE");
    return encodeMap({ session_id: aad.sessionId, seq: aad.seq, op: aad.op });
}

export function encodeFrameRequest(aadBytes: Bytes, ct: Bytes): CanonicalEnvelope {
    check(hasLength(ct, MIN_CT, MAX_CT), "CT_RANGE");
    return encodeMap({ kind: "frame", aad: aadBytes, ct });
}

// WireError from the codec; WireError("MALFORMED") on any schema failure
export function decodeResponse(
    body: Bytes,
    envelopeDecode: DecodeLimits,
    aadDecode: DecodeLimits,
): OpenResultEnvelope | FrameResultEnvelope {
    const envelope = decodeCanonical(body, envelopeDecode) as ReadonlyMap<string, CanonicalValue>;
    const aadBytes = envelope.get("aad") as Bytes;
    const ct = envelope.get("ct") as Bytes;
    const aad = decodeCanonical(aadBytes, aadDecode) as ReadonlyMap<string, CanonicalValue>;
    if (envelope.get("kind") === "open_result") {
        return {
            kind: "open_result",
            aadBytes,
            aad: {
                sessionId: aad.get("session_id") as Bytes | null,
                requestId: aad.get("request_id") as Bytes,
            },
            ct,
        };
    }
    return {
        kind: "frame_result",
        aadBytes,
        aad: {
            sessionId: aad.get("session_id") as Bytes,
            seq: aad.get("seq") as number,
            op: aad.get("op") as string,
        },
        ct,
    };
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
