// Channel wire codec (INC-2-API §7.3, §3.1; API-TL §3). Constants and types final; functions stub → T-15.
// Every function goes through encodeCanonical/decodeCanonical only. The nonce builder is not here (R-5).
import {
    CapabilityError,
    type Bytes,
    type CanonicalEnvelope,
    type ClientId,
    type Crypto,
    type InstanceId,
} from "../capabilities.js";
import { utf8Encode } from "../encoding.js";
import { decodeCanonical, encodeCanonical } from "../wire/cbor.js";
import { ChannelError } from "./errors.js";
import { PROTO, WireError, type CanonicalValue, type DecodeLimits } from "../wire/types.js";
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
const SHA256_BYTES = 32;
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

function isUint(value: unknown, max: number): value is number {
    return (
        typeof value === "number" &&
        Number.isSafeInteger(value) &&
        !Object.is(value, -0) &&
        value >= 0 &&
        value <= max
    );
}

function matches(value: unknown, pattern: RegExp): value is string {
    return typeof value === "string" && pattern.test(value);
}

function hasLength(value: unknown, min: number, max = min): value is Bytes {
    return value instanceof Uint8Array && value.length >= min && value.length <= max;
}

function encodeMap(entries: Record<string, CanonicalValue>): Bytes {
    return encodeCanonical(new Map(Object.entries(entries)));
}

const ENVELOPE_KEYS = ["aad", "ct", "kind"];
const OPEN_RESULT_AAD_KEYS = ["request_id", "seq", "session_id"];
const FRAME_AAD_KEYS = ["op", "seq", "session_id"];

const SUCCESS_KEYS = ["ok", "payload"];
const FAILURE_KEYS = ["error", "ok"];

function invalidResponse(): never {
    throw new ChannelError("INVALID_RESPONSE");
}

// Every decode failure, whatever its cause, is INVALID_RESPONSE: the plaintext has already authenticated.
function decodePlaintext(pt: Bytes, limits: DecodeLimits): CanonicalValue {
    try {
        return decodeCanonical(pt, limits);
    } catch {
        return invalidResponse();
    }
}

// {ok: true, payload} or {ok: false, error}, each with exactly the `extra` keys besides.
function resultBody(
    value: CanonicalValue,
    extra: readonly string[],
):
    | { readonly map: ReadonlyMap<string, CanonicalValue>; readonly body: OpenResultBody }
    | undefined {
    const success = exactMap(value, [...SUCCESS_KEYS, ...extra]);
    if (success?.get("ok") === true) {
        return {
            map: success,
            body: { ok: true, payload: success.get("payload") as CanonicalValue },
        };
    }
    const failure = exactMap(value, [...FAILURE_KEYS, ...extra]);
    const error = failure?.get("error");
    if (failure?.get("ok") === false && matches(error, ERROR_CODE_PATTERN)) {
        return { map: failure, body: { ok: false, error } };
    }
    return undefined;
}

function malformed(): never {
    throw new WireError("MALFORMED");
}

// The map, if it has exactly these keys; otherwise undefined.
function exactMap(
    value: CanonicalValue,
    keys: readonly string[],
): ReadonlyMap<string, CanonicalValue> | undefined {
    if (!(value instanceof Map)) {
        return undefined;
    }
    const map = value as ReadonlyMap<string, CanonicalValue>;
    return map.size === keys.length && keys.every((key) => map.has(key)) ? map : undefined;
}

function sameBytes(a: Bytes, b: Bytes): boolean {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function openResultAad(value: CanonicalValue): OpenResultAadFields | undefined {
    const map = exactMap(value, OPEN_RESULT_AAD_KEYS);
    const sessionId = map?.get("session_id");
    const requestId = map?.get("request_id");
    return map?.get("seq") === 0 &&
        (sessionId === null || hasLength(sessionId, ID_BYTES)) &&
        hasLength(requestId, ID_BYTES)
        ? { sessionId, requestId }
        : undefined;
}

function frameAad(value: CanonicalValue): FrameAadFields | undefined {
    const map = exactMap(value, FRAME_AAD_KEYS);
    const sessionId = map?.get("session_id");
    const seq = map?.get("seq");
    const op = map?.get("op");
    return hasLength(sessionId, ID_BYTES) && isUint(seq, MAX_SEQ) && matches(op, OP_NAME_PATTERN)
        ? { sessionId, seq, op }
        : undefined;
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
    const envelope = exactMap(decodeCanonical(body, envelopeDecode), ENVELOPE_KEYS) ?? malformed();
    const kind = envelope.get("kind");
    const aadBytes = envelope.get("aad");
    const ct = envelope.get("ct");
    if (
        (kind !== "open_result" && kind !== "frame_result") ||
        !(aadBytes instanceof Uint8Array) ||
        !hasLength(ct, MIN_CT, MAX_CT)
    ) {
        return malformed();
    }
    const aadValue = decodeCanonical(aadBytes, aadDecode);
    if (!sameBytes(encodeCanonical(aadValue), aadBytes)) {
        return malformed();
    }
    return kind === "open_result"
        ? { kind, aadBytes, aad: openResultAad(aadValue) ?? malformed(), ct }
        : { kind, aadBytes, aad: frameAad(aadValue) ?? malformed(), ct };
}

// ChannelError("INVALID_RESPONSE") on any failure, incl. R-3
export function decodeOpenResultPlaintext(
    pt: Bytes,
    aad: OpenResultAadFields,
    limits: DecodeLimits,
): OpenResultBody {
    const { body } = resultBody(decodePlaintext(pt, limits), []) ?? invalidResponse();
    // R-3: a session exists exactly when the open succeeded.
    if (body.ok !== (aad.sessionId !== null)) {
        return invalidResponse();
    }
    return body;
}

// ChannelError("INVALID_RESPONSE")
export function decodeFrameResultPlaintext(pt: Bytes, limits: DecodeLimits): FrameResultBody {
    const { map, body } = resultBody(decodePlaintext(pt, limits), ["re"]) ?? invalidResponse();
    const re = map.get("re");
    if (!isUint(re, MAX_SEQ)) {
        return invalidResponse();
    }
    return { re, ...body };
}

// 47 B; RangeError on input; CapabilityError("INVALID_RESPONSE") if sha256 is not 32 B
export async function hpkeInfo(
    crypto: Pick<Crypto, "sha256">,
    ikPub: Bytes,
    prekeyId: number,
): Promise<Bytes> {
    check(hasLength(ikPub, KEY_BYTES), "IK_PUB_RANGE");
    check(isUint(prekeyId, MAX_UINT32), "PREKEY_ID_RANGE");
    const proto = utf8Encode(PROTO);
    const ikHash = await crypto.sha256(ikPub);
    // The digest is width-checked like every other layout input (SR-14): a bad port fails closed.
    if (!hasLength(ikHash, SHA256_BYTES)) {
        throw new CapabilityError("INVALID_RESPONSE");
    }
    const info = new Uint8Array(proto.length + ikHash.length + 4);
    info.set(proto);
    info.set(ikHash, proto.length);
    new DataView(info.buffer).setUint32(proto.length + ikHash.length, prekeyId);
    return info;
}
