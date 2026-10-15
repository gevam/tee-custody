// Client session and decrypt-side frame helpers (INC-2-API §7.4; API-TL §3; D2-16).
// None of the helpers seals. The nonce builder is module-private to this file (R-5).
import {
    CapabilityError,
    type Bytes,
    type ClientId,
    type Crypto,
    type InstanceId,
} from "../capabilities.js";
import type { CanonicalValue } from "../wire/types.js";
import { ChannelError, type RemoteErrorCode } from "./errors.js";
import type { ChannelLimits } from "./types.js";
import { decodeOpenResultPlaintext, decodeResponse, type FrameAadFields } from "./wire.js";

const SESSION_TOKEN = Symbol("Session");

// The response router a Session and an open share (ChannelClient implements it; internal).
export interface SessionLink {
    // ChannelError("TRANSPORT") on a transport failure
    post(instanceId: InstanceId, envelope: Bytes): Promise<void>;
    // Resolves with the first body `match` accepts; rejects with what `match` throws, or TIMEOUT.
    wait<T>(route: ClientId, owner: object, match: (body: Bytes) => Promise<T | undefined>): Promise<T>;
    // Rejects every pending wait of `owner` with `error`.
    cancel(owner: object, error: Error): void;
    // A route stays known (its cursor kept) while attached.
    attach(route: ClientId): void;
    detach(route: ClientId): void;
}

// T-26 design (API-TL §3). The Session takes ownership of both key buffers.
export interface SessionInit {
    readonly sessionId: Bytes;
    readonly instanceId: InstanceId;
    readonly clientId: ClientId;
    readonly keyC2t: Bytes;
    readonly keyT2c: Bytes;
    readonly crypto: Pick<Crypto, "aes256GcmEncrypt" | "aes256GcmDecrypt">;
    readonly limits: ChannelLimits;
    readonly link: SessionLink;
}

const REMOTE_ERROR_CODES: ReadonlySet<string> = new Set<RemoteErrorCode>([
    "INVALID_FRAME",
    "AUTHENTICATION_FAILED",
    "REPLAYED_OR_OUT_OF_ORDER",
    "UNKNOWN_CLIENT",
    "UNKNOWN_OPERATION",
    "NOT_AUTHORIZED",
    "LIMIT_EXCEEDED",
    "RECORD_NOT_FOUND",
    "BACKEND_UNAVAILABLE",
    "INTERNAL",
]);

// Wire error codes outside RemoteErrorCode map to "UNKNOWN" (INC-2-API §7.5).
function remoteCode(error: string): RemoteErrorCode {
    return REMOTE_ERROR_CODES.has(error) ? (error as RemoteErrorCode) : "UNKNOWN";
}

// INC-2-API §2 session AEAD nonce: 0x00000000 ‖ u64be(seq). Module-private (R-5).
function nonce(seq: number): Bytes {
    const out = new Uint8Array(12);
    new DataView(out.buffer).setBigUint64(4, BigInt(seq));
    return out;
}

function sameBytes(a: Bytes, b: Bytes): boolean {
    return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

function decodeOrUndefined(
    envelope: Bytes,
    limits: Pick<ChannelLimits, "envelopeDecode" | "aadDecode">,
): ReturnType<typeof decodeResponse> | undefined {
    try {
        return decodeResponse(envelope, limits.envelopeDecode, limits.aadDecode);
    } catch {
        return undefined;
    }
}

// The t2c plaintext, or undefined when the AEAD check fails (the queue is untrusted: ignore).
async function openT2c(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    key: Bytes,
    seq: number,
    aadBytes: Bytes,
    ct: Bytes,
): Promise<Bytes | undefined> {
    try {
        return await crypto.aes256GcmDecrypt(key, nonce(seq), aadBytes, ct);
    } catch {
        return undefined;
    }
}

// Runs a Crypto-port step; any failure is fail-closed CRYPTO_UNAVAILABLE (INC-2-API §7.5). The detail is the
// port's capability code, or INVALID_RESPONSE when the port's output was unusable.
export async function viaCrypto<T>(step: () => T | Promise<T>): Promise<T> {
    try {
        return await step();
    } catch (error) {
        throw new ChannelError(
            "CRYPTO_UNAVAILABLE",
            error instanceof CapabilityError ? error.code : "INVALID_RESPONSE",
        );
    }
}

export function createSession(init: SessionInit): Session {
    return new Session(SESSION_TOKEN, init);
}

// constructed only by ChannelClient
export class Session {
    readonly sessionId: Bytes;
    readonly instanceId: InstanceId;
    readonly clientId: ClientId;

    // TypeError("INVALID_CONFIG") unless token is the module-private symbol of session.ts
    readonly #sessionId: Bytes;
    readonly #keyC2t: Bytes;
    readonly #keyT2c: Bytes;
    readonly #init: SessionInit;

    constructor(token: symbol, init: SessionInit) {
        if (token !== SESSION_TOKEN) {
            throw new TypeError("INVALID_CONFIG");
        }
        this.sessionId = init.sessionId.slice();
        this.#sessionId = init.sessionId.slice();
        this.instanceId = init.instanceId;
        this.clientId = init.clientId;
        this.#keyC2t = init.keyC2t;
        this.#keyT2c = init.keyT2c;
        this.#init = init;
        init.link.attach(this.clientId);
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
export async function readOpenResult(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    keyT2c: Bytes,
    requestId: Bytes,
    envelope: Bytes,
    limits: ChannelLimits,
): Promise<OpenResultMatch | undefined> {
    const decoded = decodeOrUndefined(envelope, limits);
    if (decoded?.kind !== "open_result" || !sameBytes(decoded.aad.requestId, requestId)) {
        return undefined;
    }
    // D2-3: the open_result is the one use of t2c nonce 0.
    const pt = await openT2c(crypto, keyT2c, 0, decoded.aadBytes, decoded.ct);
    if (pt === undefined) {
        return undefined;
    }
    const body = decodeOpenResultPlaintext(pt, decoded.aad, limits.payloadDecode);
    return body.ok
        ? // R-3 is enforced by decodeOpenResultPlaintext: ok implies a session id.
          { ok: true, sessionId: decoded.aad.sessionId as Bytes, payload: body.payload }
        : { ok: false, error: remoteCode(body.error) };
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
