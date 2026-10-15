// Client session and decrypt-side frame helpers (INC-2-API §7.4; API-TL §3; D2-16).
// None of the helpers seals. The nonce builder is module-private to this file (R-5).
import {
    CapabilityError,
    type Bytes,
    type ClientId,
    type Crypto,
    type InstanceId,
} from "../capabilities.js";
import { encodeCanonical } from "../wire/cbor.js";
import type { CanonicalValue } from "../wire/types.js";
import { ChannelError, type RemoteErrorCode } from "./errors.js";
import type { ChannelLimits } from "./types.js";
import {
    MAX_SEQ,
    OP_NAME_PATTERN,
    decodeFrameResultPlaintext,
    decodeOpenResultPlaintext,
    decodeResponse,
    encodeFrameAad,
    encodeFrameRequest,
    type FrameAadFields,
} from "./wire.js";

const SESSION_TOKEN = Symbol("Session");
const CLOSE_PAYLOAD = encodeCanonical(null);

// The response router a Session and an open share (ChannelClient implements it; internal).
export interface SessionLink {
    // ChannelError("TRANSPORT") on a transport failure
    post(instanceId: InstanceId, envelope: Bytes): Promise<void>;
    // Resolves with the first body `match` accepts; rejects with what `match` throws, or TIMEOUT.
    wait<T>(
        route: ClientId,
        owner: object,
        match: (body: Bytes) => Promise<T | undefined>,
    ): Promise<T>;
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

    readonly #sessionId: Bytes;
    readonly #keyC2t: Bytes;
    readonly #keyT2c: Bytes;
    readonly #crypto: SessionInit["crypto"];
    readonly #limits: ChannelLimits;
    readonly #link: SessionLink;
    // R-5: the next c2t seq. Only #sealNext reads or advances it; nothing ever lowers it.
    #nextC2tSeq = 0;
    // D2-3: t2c seq 0 was the open_result, so the first frame result must carry seq ≥ 1.
    #lastT2cSeq = 0;
    #pending = 0;
    #closed = false;
    #live = true;

    // TypeError("INVALID_CONFIG") unless token is the module-private symbol of session.ts
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
        this.#crypto = init.crypto;
        this.#limits = init.limits;
        this.#link = init.link;
        init.link.attach(this.clientId);
    }

    get closed(): boolean {
        return this.#closed;
    }

    async request(op: string, payload: CanonicalValue): Promise<CanonicalValue> {
        if (this.#closed) {
            throw new ChannelError("SESSION_CLOSED");
        }
        if (typeof op !== "string" || !OP_NAME_PATTERN.test(op) || op === "close") {
            throw new ChannelError("INVALID_ARGUMENT");
        }
        const payloadBytes = this.#encodePayload(payload);
        if (this.#pending >= this.#limits.maxInFlight) {
            throw new ChannelError("INVALID_ARGUMENT");
        }
        this.#pending += 1;
        try {
            return await this.#exchange(op, payloadBytes);
        } finally {
            this.#pending -= 1;
        }
    }

    #encodePayload(payload: CanonicalValue): Bytes {
        let bytes: Bytes;
        try {
            bytes = encodeCanonical(payload);
        } catch {
            throw new ChannelError("INVALID_ARGUMENT");
        }
        if (bytes.length > this.#limits.maxPayloadBytes) {
            throw new ChannelError("INVALID_ARGUMENT");
        }
        return bytes;
    }

    // Seals once, posts once, and waits for the matching result. Never re-seals, never retries (R-5).
    async #exchange(op: string, payloadBytes: Bytes): Promise<CanonicalValue> {
        const { seq, envelope } = await this.#sealNext(op, payloadBytes);
        await this.#link.post(this.instanceId, envelope);
        if (!this.#live) {
            throw new ChannelError("SESSION_CLOSED");
        }
        const match = await this.#link.wait(this.clientId, this, async (body) => {
            const result = await readFrameResult(
                this.#crypto,
                this.#keyT2c,
                this.#sessionId,
                seq,
                this.#lastT2cSeq,
                body,
                this.#limits,
            );
            if (result?.op !== op) {
                return undefined;
            }
            this.#lastT2cSeq = result.seq;
            return result;
        });
        if (!match.ok) {
            throw new ChannelError("REMOTE_ERROR", match.error);
        }
        return match.payload;
    }

    // The one sealing method (D2-16). seq is taken and the counter advanced before the first await.
    async #sealNext(op: string, payloadBytes: Bytes): Promise<{ seq: number; envelope: Bytes }> {
        const seq = this.#nextC2tSeq;
        if (seq > MAX_SEQ) {
            this.#shutdown();
            throw new ChannelError("SEQUENCE_EXHAUSTED");
        }
        this.#nextC2tSeq = seq + 1;
        const aadBytes = encodeFrameAad({ sessionId: this.#sessionId, seq, op });
        const envelope = await viaCrypto(async () =>
            encodeFrameRequest(
                aadBytes,
                await this.#crypto.aes256GcmEncrypt(
                    this.#keyC2t,
                    nonce(seq),
                    aadBytes,
                    payloadBytes,
                ),
            ),
        );
        return { seq, envelope };
    }

    // Local close: keys zeroed, pending requests released, route detached.
    #shutdown(): void {
        if (!this.#live) {
            return;
        }
        this.#live = false;
        this.#closed = true;
        this.#keyC2t.fill(0);
        this.#keyT2c.fill(0);
        this.#link.cancel(this, new ChannelError("SESSION_CLOSED"));
        this.#link.detach(this.clientId);
    }

    // sends op "close"; idempotent; destroys keys even on failure
    async close(): Promise<void> {
        if (this.#closed) {
            return;
        }
        this.#closed = true;
        try {
            await this.#exchange("close", CLOSE_PAYLOAD);
        } finally {
            this.#shutdown();
        }
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
export async function readFrameResult(
    crypto: Pick<Crypto, "aes256GcmDecrypt">,
    keyT2c: Bytes,
    sessionId: Bytes,
    re: number,
    lastSeq: number,
    envelope: Bytes,
    limits: ChannelLimits,
): Promise<FrameResultMatch | undefined> {
    const decoded = decodeOrUndefined(envelope, limits);
    // D2-3: t2c seq 0 belongs to the open_result, so a frame result needs seq ≥ 1 whatever lastSeq says.
    if (
        decoded?.kind !== "frame_result" ||
        !sameBytes(decoded.aad.sessionId, sessionId) ||
        decoded.aad.seq <= Math.max(lastSeq, 0)
    ) {
        return undefined;
    }
    const { seq, op } = decoded.aad;
    const pt = await openT2c(crypto, keyT2c, seq, decoded.aadBytes, decoded.ct);
    if (pt === undefined) {
        return undefined;
    }
    const body = decodeFrameResultPlaintext(pt, limits.payloadDecode);
    if (body.re !== re) {
        return undefined;
    }
    return body.ok
        ? { seq, op, re, ok: true, payload: body.payload }
        : { seq, op, re, ok: false, error: remoteCode(body.error) };
}
