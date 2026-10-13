// FR-4 / SR-3 / SR-14: the Core channel wire layer (INC-2-API §2, §3.1, §7.3; API-TL §3), checked
// against bytes built independently from the CDDL with Core's canonical encoder (INC-1).
// The wire module is internal (not exported from index.ts), so it is imported by path.
//
// Owning task: T-15. Expected failure on trunk: Error("NOT_IMPLEMENTED: T-15").
import { createHash } from "node:crypto";

import { ChannelError, WireError, encodeCanonical, type CanonicalValue } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { nodeCrypto } from "../support/node-crypto.js";
import {
    decodeFrameResultPlaintext,
    decodeOpenResultPlaintext,
    decodeResponse,
    encodeFrameAad,
    encodeFrameRequest,
    encodeOpenAad,
    encodeOpenPlaintext,
    encodeOpenRequest,
    hpkeInfo,
} from "../../packages/teecustody-core/src/channel/wire.js";

const CLIENT = "a1".repeat(16);
const INSTANCE = "b2".repeat(16);
const RID = new Uint8Array(16).fill(9);
const SID = new Uint8Array(16).fill(7);
const ENVELOPE = { maxBytes: 65_536, maxDepth: 2, maxItems: 16 };
const AAD = { maxBytes: 512, maxDepth: 2, maxItems: 16 };
const PAYLOAD = { maxBytes: 32_768, maxDepth: 16, maxItems: 4096 };

const m = (entries: Record<string, CanonicalValue>): ReadonlyMap<string, CanonicalValue> =>
    new Map(Object.entries(entries));
const same = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));

function rangeError(fn: () => unknown, pattern = /_RANGE$/): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    if (thrown instanceof Error && thrown.message.startsWith("NOT_IMPLEMENTED")) {
        throw thrown;
    }
    expect(thrown).toBeInstanceOf(RangeError);
    expect((thrown as RangeError).message).toMatch(pattern);
}

describe("T-15 request encoders produce exactly the CDDL bytes", () => {
    const openAad = {
        clientId: CLIENT,
        instanceId: INSTANCE,
        prekeyId: 5,
        requestId: RID,
        timestamp: 1_900_000_000,
    };

    it("encodes the open AAD canonically with the protocol string", () => {
        const expected = encodeCanonical(
            m({
                proto: "tee-chan-v1",
                client_id: CLIENT,
                instance_id: INSTANCE,
                prekey_id: 5,
                request_id: RID,
                timestamp: 1_900_000_000,
            }),
        );
        expect(same(encodeOpenAad(openAad), expected)).toBe(true);
    });

    it.each([
        ["client id uppercase", { clientId: CLIENT.toUpperCase() }],
        ["client id newline", { clientId: `${CLIENT}\n` }],
        ["instance id short", { instanceId: INSTANCE.slice(1) }],
        ["prekey id over uint32", { prekeyId: 2 ** 32 }],
        ["prekey id negative", { prekeyId: -1 }],
        ["prekey id fractional", { prekeyId: 1.5 }],
        ["request id 15 bytes", { requestId: new Uint8Array(15) }],
        ["timestamp over 2^53-1", { timestamp: 2 ** 53 }],
        ["timestamp negative", { timestamp: -1 }],
        ["timestamp NaN", { timestamp: Number.NaN }],
    ])("rejects %s before encoding", (_name, override) => {
        rangeError(() => encodeOpenAad({ ...openAad, ...override }));
    });

    it("encodes the open plaintexts: open_session and enroll", () => {
        const cs = new Uint8Array(32).fill(1);
        const keyId = new Uint8Array(16).fill(2);
        expect(
            same(
                encodeOpenPlaintext({ op: "open_session", clientId: CLIENT, cs, keyId, epoch: 3 }),
                encodeCanonical(m({ op: "open_session", cs, key_id: keyId, epoch: 3 })),
            ),
        ).toBe(true);
        expect(
            same(encodeOpenPlaintext({ op: "enroll" }), encodeCanonical(m({ op: "enroll" }))),
        ).toBe(true);
    });

    it.each([
        ["cs 31 bytes", { cs: new Uint8Array(31) }],
        ["key id 15 bytes", { keyId: new Uint8Array(15) }],
        ["epoch over uint32", { epoch: 2 ** 32 }],
        ["epoch negative", { epoch: -1 }],
    ])("rejects an open_session payload with %s", (_name, override) => {
        const base = {
            op: "open_session" as const,
            clientId: CLIENT,
            cs: new Uint8Array(32),
            keyId: new Uint8Array(16),
            epoch: 0,
        };
        rangeError(() => encodeOpenPlaintext({ ...base, ...override }));
    });

    it("wraps the open request and the frame request as the CDDL envelopes", () => {
        const aad = new Uint8Array([1, 2, 3]);
        const enc = new Uint8Array(32).fill(4);
        const ct = new Uint8Array(40).fill(5);
        expect(
            same(
                encodeOpenRequest(aad, enc, ct),
                encodeCanonical(m({ kind: "open", aad, enc, ct })),
            ),
        ).toBe(true);
        expect(
            same(encodeFrameRequest(aad, ct), encodeCanonical(m({ kind: "frame", aad, ct }))),
        ).toBe(true);
    });

    it("encodes the frame AAD and rejects out-of-range fields with named errors", () => {
        const aad = { sessionId: SID, seq: 4, op: "test.echo" };
        expect(
            same(
                encodeFrameAad(aad),
                encodeCanonical(m({ session_id: SID, seq: 4, op: "test.echo" })),
            ),
        ).toBe(true);
        rangeError(() => encodeFrameAad({ ...aad, seq: 2 ** 53 }), /^SEQ_RANGE$/);
        rangeError(() => encodeFrameAad({ ...aad, seq: -1 }), /^SEQ_RANGE$/);
        rangeError(() => encodeFrameAad({ ...aad, op: "Bad Op" }), /^OP_RANGE$/);
        rangeError(() => encodeFrameAad({ ...aad, op: "" }), /^OP_RANGE$/);
        rangeError(
            () => encodeFrameAad({ ...aad, sessionId: new Uint8Array(15) }),
            /^SESSION_ID_RANGE$/,
        );
    });
});

describe("T-15 hpkeInfo", () => {
    it("is ascii(PROTO) || SHA-256(IK_pub) || u32be(prekey_id), 47 bytes", async () => {
        const ik = new Uint8Array(32).fill(8);
        const expected = Buffer.concat([
            Buffer.from("tee-chan-v1"),
            createHash("sha256").update(ik).digest(),
            Buffer.from([0, 0, 1, 2]),
        ]);
        const got = await hpkeInfo(nodeCrypto(), ik, 0x0102);
        expect(got).toHaveLength(47);
        expect(Buffer.from(got).equals(expected)).toBe(true);
    });

    it("rejects a short key or an out-of-range pre-key id", async () => {
        for (const call of [
            () => hpkeInfo(nodeCrypto(), new Uint8Array(31), 0),
            () => hpkeInfo(nodeCrypto(), new Uint8Array(32), 2 ** 32),
            () => hpkeInfo(nodeCrypto(), new Uint8Array(32), -1),
        ]) {
            const error = await Promise.resolve()
                .then(call)
                .then(
                    () => undefined,
                    (e: unknown) => e,
                );
            if (error instanceof Error && error.message.startsWith("NOT_IMPLEMENTED")) {
                throw error;
            }
            expect(error).toBeInstanceOf(RangeError);
        }
    });
});

describe("T-15 response decoding", () => {
    const openAad = (over: Record<string, CanonicalValue> = {}): Uint8Array =>
        encodeCanonical(m({ session_id: SID, request_id: RID, seq: 0, ...over }));
    const frameAad = (over: Record<string, CanonicalValue> = {}): Uint8Array =>
        encodeCanonical(m({ session_id: SID, seq: 3, op: "test.echo", ...over }));
    const ct = new Uint8Array(32).fill(6);
    const envelope = (entries: Record<string, CanonicalValue>): Uint8Array =>
        encodeCanonical(m(entries));

    it("decodes an open_result envelope, keeping the exact AAD bytes for AEAD", () => {
        const aad = openAad();
        const got = decodeResponse(envelope({ kind: "open_result", aad, ct }), ENVELOPE, AAD);
        expect(got.kind).toBe("open_result");
        expect(same(got.aadBytes, aad)).toBe(true);
        expect(got.aad).toMatchObject({ requestId: RID });
        expect((got.aad as { sessionId: Uint8Array | null }).sessionId).toEqual(SID);
        expect(same(got.ct, ct)).toBe(true);
    });

    it("decodes an open_result refusal (nil session id) and a frame_result envelope", () => {
        const refused = decodeResponse(
            envelope({ kind: "open_result", aad: openAad({ session_id: null }), ct }),
            ENVELOPE,
            AAD,
        );
        expect((refused.aad as { sessionId: unknown }).sessionId).toBeNull();
        const frame = decodeResponse(
            envelope({ kind: "frame_result", aad: frameAad(), ct }),
            ENVELOPE,
            AAD,
        );
        expect(frame.kind).toBe("frame_result");
        expect(frame.aad).toMatchObject({ seq: 3, op: "test.echo" });
    });

    it.each<[string, () => Uint8Array]>([
        ["unknown envelope key", () => envelope({ kind: "open_result", aad: openAad(), ct, x: 1 })],
        ["unknown kind", () => envelope({ kind: "open", aad: openAad(), ct })],
        ["request kind in a response", () => envelope({ kind: "frame", aad: frameAad(), ct })],
        ["aad not bytes", () => envelope({ kind: "open_result", aad: "text", ct })],
        [
            "ct too short",
            () => envelope({ kind: "open_result", aad: openAad(), ct: new Uint8Array(15) }),
        ],
        [
            "ct too long",
            () => envelope({ kind: "frame_result", aad: frameAad(), ct: new Uint8Array(32_785) }),
        ],
        [
            "open_result seq not 0",
            () => envelope({ kind: "open_result", aad: openAad({ seq: 1 }), ct }),
        ],
        [
            "open_result session id 15 bytes",
            () =>
                envelope({
                    kind: "open_result",
                    aad: openAad({ session_id: new Uint8Array(15) }),
                    ct,
                }),
        ],
        [
            "open_result request id 15 bytes",
            () =>
                envelope({
                    kind: "open_result",
                    aad: openAad({ request_id: new Uint8Array(15) }),
                    ct,
                }),
        ],
        [
            "frame op uppercase",
            () => envelope({ kind: "frame_result", aad: frameAad({ op: "Test" }), ct }),
        ],
        [
            "frame seq 2^53",
            () => envelope({ kind: "frame_result", aad: frameAad({ seq: 2n ** 53n }), ct }),
        ],
        [
            "frame aad extra key",
            () => envelope({ kind: "frame_result", aad: frameAad({ x: 1 }), ct }),
        ],
        ["not a map", () => encodeCanonical([1, 2])],
        ["garbage", () => new Uint8Array([0xff, 0xff])],
        ["empty", () => new Uint8Array(0)],
    ])("rejects %s with a WireError", (_name, make) => {
        expectWire(() => decodeResponse(make(), ENVELOPE, AAD));
    });

    it("rejects a non-canonical envelope (keys out of canonical order)", () => {
        const aad = openAad();
        // map(3): "ct", "kind", "aad" in non-canonical order, hand-assembled
        const bytes = Buffer.concat([
            Buffer.from([0xa3, 0x62, 0x63, 0x74, 0x58, 0x20]),
            Buffer.from(ct),
            Buffer.from([0x64, 0x6b, 0x69, 0x6e, 0x64, 0x6b]),
            Buffer.from("open_result"),
            Buffer.from([0x63, 0x61, 0x61, 0x64, 0x58, aad.length]),
            Buffer.from(aad),
        ]);
        expectWire(() => decodeResponse(new Uint8Array(bytes), ENVELOPE, AAD));
    });

    const asOpenAad = (sessionId: Uint8Array | null) => ({ sessionId, requestId: RID });

    it("enforces R-3: ok:true needs a session id, ok:false must not have one", () => {
        const okBody = encodeCanonical(m({ ok: true, payload: null }));
        const errBody = encodeCanonical(m({ ok: false, error: "INTERNAL" }));
        expect(decodeOpenResultPlaintext(okBody, asOpenAad(SID), PAYLOAD)).toEqual({
            ok: true,
            payload: null,
        });
        expect(decodeOpenResultPlaintext(errBody, asOpenAad(null), PAYLOAD)).toEqual({
            ok: false,
            error: "INTERNAL",
        });
        invalidResponse(() => decodeOpenResultPlaintext(okBody, asOpenAad(null), PAYLOAD));
        invalidResponse(() => decodeOpenResultPlaintext(errBody, asOpenAad(SID), PAYLOAD));
    });

    it.each<[string, Record<string, CanonicalValue>]>([
        ["ok missing", { payload: null }],
        ["ok not boolean", { ok: 1, payload: null }],
        ["error lower-case", { ok: false, error: "internal" }],
        ["error too long", { ok: false, error: "A".repeat(65) }],
        ["payload missing on success", { ok: true }],
        ["extra key", { ok: true, payload: null, x: 1 }],
        ["error and payload together", { ok: false, error: "X", payload: null }],
    ])("rejects an open-result plaintext with %s as INVALID_RESPONSE", (_name, body) => {
        invalidResponse(() =>
            decodeOpenResultPlaintext(encodeCanonical(m(body)), asOpenAad(null), PAYLOAD),
        );
    });

    it("decodes frame-result plaintexts and rejects schema violations", () => {
        expect(
            decodeFrameResultPlaintext(
                encodeCanonical(m({ re: 4, ok: true, payload: "x" })),
                PAYLOAD,
            ),
        ).toEqual({
            re: 4,
            ok: true,
            payload: "x",
        });
        expect(
            decodeFrameResultPlaintext(
                encodeCanonical(m({ re: 0, ok: false, error: "NOT_AUTHORIZED" })),
                PAYLOAD,
            ),
        ).toEqual({ re: 0, ok: false, error: "NOT_AUTHORIZED" });
        for (const bad of [
            { ok: true, payload: null },
            { re: -1, ok: true, payload: null },
            { re: 2n ** 53n, ok: true, payload: null },
            { re: 1, ok: false, error: "lower" },
            { re: 1, ok: true, payload: null, x: 1 },
        ]) {
            invalidResponse(() => decodeFrameResultPlaintext(encodeCanonical(m(bad)), PAYLOAD));
        }
        invalidResponse(() => decodeFrameResultPlaintext(new Uint8Array([0xff]), PAYLOAD));
        // canonical CBOR has no floats, so the encoder cannot build this; hand-encode {ok: true,
        // re: 1.5 (half-float f9 3e00), payload: null} in canonical key order (ok, re, payload)
        const withFloat = Buffer.concat([
            Buffer.from([0xa3, 0x62, 0x6f, 0x6b, 0xf5, 0x62, 0x72, 0x65, 0xf9, 0x3e, 0x00, 0x67]),
            Buffer.from("payload"),
            Buffer.from([0xf6]),
        ]);
        invalidResponse(() => decodeFrameResultPlaintext(new Uint8Array(withFloat), PAYLOAD));
    });
});

function stub(error: unknown): void {
    if (error instanceof Error && error.message.startsWith("NOT_IMPLEMENTED")) {
        throw error;
    }
}

function expectWire(fn: () => unknown): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    stub(thrown);
    expect(thrown).toBeInstanceOf(WireError);
}

function invalidResponse(fn: () => unknown): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    stub(thrown);
    expect(thrown).toBeInstanceOf(ChannelError);
    expect((thrown as ChannelError).code).toBe("INVALID_RESPONSE");
}
