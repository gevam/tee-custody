// T-15: Core channel wire codec (INC-2-API §2, §3.1, §7.3; API-TL §3; SR-3, SR-14).
// Expected bytes are hex literals computed independently with the Python canonical codec.
import { afterEach, describe, expect, it, vi } from "vitest";

import { ChannelError } from "../../src/channel/errors.js";
import * as cbor from "../../src/wire/cbor.js";
import { WireError, type CanonicalValue, type WireErrorCode } from "../../src/wire/types.js";
import {
    decodeFrameResultPlaintext,
    decodeOpenResultPlaintext,
    decodeResponse,
    encodeFrameAad,
    encodeFrameRequest,
    encodeOpenAad,
    encodeOpenPlaintext,
    encodeOpenRequest,
} from "../../src/channel/wire.js";

// Pass-through spies: a test can assert the encoder/decoder was (not) called, or substitute one call.
vi.mock("../../src/wire/cbor.js", async (importOriginal) => {
    const real = await importOriginal<typeof import("../../src/wire/cbor.js")>();
    return {
        encodeCanonical: vi.fn(real.encodeCanonical),
        decodeCanonical: vi.fn(real.decodeCanonical),
    };
});

afterEach(() => {
    vi.mocked(cbor.encodeCanonical).mockClear();
    vi.mocked(cbor.decodeCanonical).mockClear();
});

const CLIENT = "a1".repeat(16);
const INSTANCE = "b2".repeat(16);
const RID = new Uint8Array(16).fill(9);
const SID = new Uint8Array(16).fill(7);

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

const OPEN_AAD = {
    clientId: CLIENT,
    instanceId: INSTANCE,
    prekeyId: 5,
    requestId: RID,
    timestamp: 1_900_000_000,
};
const OPEN_SESSION = {
    op: "open_session" as const,
    clientId: CLIENT,
    cs: new Uint8Array(32).fill(1),
    keyId: new Uint8Array(16).fill(2),
    epoch: 3,
};
const FRAME_AAD = { sessionId: SID, seq: 4, op: "test.echo" };

describe("criterion 1: request encoders produce the CDDL bytes", () => {
    it("encodes open-aad with proto and exactly the six CDDL keys", () => {
        expect(hex(encodeOpenAad(OPEN_AAD))).toBe(
            "a6" +
                "6570726f746f" +
                "6b7465652d6368616e2d7631" +
                "69636c69656e745f6964" +
                "7820" +
                "61".concat("31").repeat(16) +
                "697072656b65795f6964" +
                "05" +
                "6974696d657374616d70" +
                "1a713fb300" +
                "6a726571756573745f6964" +
                "50" +
                "09".repeat(16) +
                "6b696e7374616e63655f6964" +
                "7820" +
                "62".concat("32").repeat(16),
        );
    });

    it("encodes the open_session plaintext without the client id", () => {
        expect(hex(encodeOpenPlaintext(OPEN_SESSION))).toBe(
            "a4" +
                "626373" +
                "5820" +
                "01".repeat(32) +
                "626f70" +
                "6c6f70656e5f73657373696f6e" +
                "6565706f6368" +
                "03" +
                "666b65795f6964" +
                "50" +
                "02".repeat(16),
        );
    });

    it("encodes the enroll plaintext as {op: enroll}", () => {
        expect(hex(encodeOpenPlaintext({ op: "enroll" }))).toBe("a1626f7066656e726f6c6c");
    });

    it("wraps the open request envelope", () => {
        const got = encodeOpenRequest(
            new Uint8Array([1, 2, 3]),
            new Uint8Array(32).fill(4),
            new Uint8Array(16).fill(5),
        );
        expect(hex(got)).toBe(
            "a4" +
                "626374" +
                "50" +
                "05".repeat(16) +
                "63616164" +
                "43010203" +
                "63656e63" +
                "5820" +
                "04".repeat(32) +
                "646b696e64" +
                "646f70656e",
        );
    });

    it("encodes frame-aad", () => {
        expect(hex(encodeFrameAad(FRAME_AAD))).toBe(
            "a3" +
                "626f70" +
                "69746573742e6563686f" +
                "63736571" +
                "04" +
                "6a73657373696f6e5f6964" +
                "50" +
                "07".repeat(16),
        );
    });

    it("wraps the frame request envelope", () => {
        const got = encodeFrameRequest(new Uint8Array([1, 2, 3]), new Uint8Array(16).fill(5));
        expect(hex(got)).toBe(
            "a3" +
                "626374" +
                "50" +
                "05".repeat(16) +
                "63616164" +
                "43010203" +
                "646b696e64" +
                "656672616d65",
        );
    });

    it("encodes the CDDL maxima: seq and timestamp 2^53-1, prekey id and epoch 2^32-1", () => {
        expect(hex(encodeFrameAad({ ...FRAME_AAD, seq: 2 ** 53 - 1 }))).toContain(
            "63736571" + "1b001fffffffffffff",
        );
        expect(
            hex(encodeOpenAad({ ...OPEN_AAD, timestamp: 2 ** 53 - 1, prekeyId: 2 ** 32 - 1 })),
        ).toContain(
            "697072656b65795f6964" + "1affffffff" + "6974696d657374616d70" + "1b001fffffffffffff",
        );
        expect(hex(encodeOpenPlaintext({ ...OPEN_SESSION, epoch: 2 ** 32 - 1 }))).toContain(
            "6565706f6368" + "1affffffff",
        );
    });

    it("accepts the CDDL minima: zero values and the shortest ct", () => {
        expect(hex(encodeFrameAad({ ...FRAME_AAD, seq: 0, op: "a" }))).toBe(
            "a3" +
                "626f70" +
                "6161" +
                "63736571" +
                "00" +
                "6a73657373696f6e5f6964" +
                "50" +
                "07".repeat(16),
        );
        expect(encodeOpenAad({ ...OPEN_AAD, timestamp: 0, prekeyId: 0 })).toBeInstanceOf(
            Uint8Array,
        );
        expect(
            hex(encodeOpenRequest(new Uint8Array(0), new Uint8Array(32), new Uint8Array(2048))),
        ).toContain("626374" + "590800");
        expect(hex(encodeFrameRequest(new Uint8Array(0), new Uint8Array(32_784)))).toContain(
            "626374" + "598010",
        );
    });
});

function expectRangeError(fn: () => unknown, code: string): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    expect(thrown).toBeInstanceOf(RangeError);
    expect((thrown as RangeError).message).toBe(code);
}

// Values the type system forbids but a caller could still pass at runtime.
const forced = (value: unknown): never => value as never;

describe("criterion 2: builders reject out-of-range input before encoding (SR-3, SR-14)", () => {
    const openAadCases: readonly (readonly [string, Partial<Record<string, unknown>>])[] = [
        ["CLIENT_ID_RANGE", { clientId: CLIENT.toUpperCase() }],
        ["CLIENT_ID_RANGE", { clientId: CLIENT.slice(1) }],
        ["CLIENT_ID_RANGE", { clientId: `${CLIENT}0` }],
        ["CLIENT_ID_RANGE", { clientId: `${CLIENT}\n` }],
        ["CLIENT_ID_RANGE", { clientId: `${CLIENT.slice(1)}g` }],
        ["CLIENT_ID_RANGE", { clientId: 7 }],
        ["INSTANCE_ID_RANGE", { instanceId: INSTANCE.slice(1) }],
        ["INSTANCE_ID_RANGE", { instanceId: INSTANCE.toUpperCase() }],
        ["INSTANCE_ID_RANGE", { instanceId: null }],
        ["PREKEY_ID_RANGE", { prekeyId: 2 ** 32 }],
        ["PREKEY_ID_RANGE", { prekeyId: -1 }],
        ["PREKEY_ID_RANGE", { prekeyId: -0 }],
        ["PREKEY_ID_RANGE", { prekeyId: 1.5 }],
        ["PREKEY_ID_RANGE", { prekeyId: Number.NaN }],
        ["PREKEY_ID_RANGE", { prekeyId: 5n }],
        ["REQUEST_ID_RANGE", { requestId: new Uint8Array(15) }],
        ["REQUEST_ID_RANGE", { requestId: new Uint8Array(17) }],
        ["REQUEST_ID_RANGE", { requestId: Array.from(RID) }],
        ["TIMESTAMP_RANGE", { timestamp: 2 ** 53 }],
        ["TIMESTAMP_RANGE", { timestamp: -1 }],
        ["TIMESTAMP_RANGE", { timestamp: 1.5 }],
        ["TIMESTAMP_RANGE", { timestamp: Number.POSITIVE_INFINITY }],
        ["TIMESTAMP_RANGE", { timestamp: Number.NaN }],
        ["TIMESTAMP_RANGE", { timestamp: 1n }],
    ];

    it.each(openAadCases)("encodeOpenAad: %s for %o", (code, override) => {
        expectRangeError(() => encodeOpenAad(forced({ ...OPEN_AAD, ...override })), code);
        expect(cbor.encodeCanonical).not.toHaveBeenCalled();
    });

    const plaintextCases: readonly (readonly [string, Partial<Record<string, unknown>>])[] = [
        ["CS_RANGE", { cs: new Uint8Array(31) }],
        ["CS_RANGE", { cs: new Uint8Array(33) }],
        ["CS_RANGE", { cs: "x".repeat(32) }],
        ["KEY_ID_RANGE", { keyId: new Uint8Array(15) }],
        ["KEY_ID_RANGE", { keyId: new Uint8Array(17) }],
        ["EPOCH_RANGE", { epoch: 2 ** 32 }],
        ["EPOCH_RANGE", { epoch: -1 }],
        ["EPOCH_RANGE", { epoch: 0.5 }],
        ["EPOCH_RANGE", { epoch: 3n }],
    ];

    it.each(plaintextCases)("encodeOpenPlaintext: %s for %o", (code, override) => {
        expectRangeError(() => encodeOpenPlaintext(forced({ ...OPEN_SESSION, ...override })), code);
        expect(cbor.encodeCanonical).not.toHaveBeenCalled();
    });

    const frameAadCases: readonly (readonly [string, Partial<Record<string, unknown>>])[] = [
        ["SESSION_ID_RANGE", { sessionId: new Uint8Array(15) }],
        ["SESSION_ID_RANGE", { sessionId: new Uint8Array(17) }],
        ["SESSION_ID_RANGE", { sessionId: null }],
        ["SEQ_RANGE", { seq: -1 }],
        ["SEQ_RANGE", { seq: 2 ** 53 }],
        ["SEQ_RANGE", { seq: 0.5 }],
        ["SEQ_RANGE", { seq: 4n }],
        ["OP_RANGE", { op: "Bad Op" }],
        ["OP_RANGE", { op: "" }],
        ["OP_RANGE", { op: "1abc" }],
        ["OP_RANGE", { op: `a${"b".repeat(64)}` }],
        ["OP_RANGE", { op: "test.echo\n" }],
        ["OP_RANGE", { op: 1 }],
    ];

    it.each(frameAadCases)("encodeFrameAad: %s for %o", (code, override) => {
        expectRangeError(() => encodeFrameAad(forced({ ...FRAME_AAD, ...override })), code);
        expect(cbor.encodeCanonical).not.toHaveBeenCalled();
    });

    it("encodeOpenRequest: ENC_RANGE and CT_RANGE (16..2048)", () => {
        const aad = new Uint8Array(3);
        const enc = new Uint8Array(32);
        const ct = new Uint8Array(16);
        expectRangeError(() => encodeOpenRequest(aad, new Uint8Array(31), ct), "ENC_RANGE");
        expectRangeError(() => encodeOpenRequest(aad, new Uint8Array(33), ct), "ENC_RANGE");
        expectRangeError(() => encodeOpenRequest(aad, enc, new Uint8Array(15)), "CT_RANGE");
        expectRangeError(() => encodeOpenRequest(aad, enc, new Uint8Array(2049)), "CT_RANGE");
        expect(cbor.encodeCanonical).not.toHaveBeenCalled();
    });

    it("encodeFrameRequest: CT_RANGE (16..32784)", () => {
        const aad = new Uint8Array(3);
        expectRangeError(() => encodeFrameRequest(aad, new Uint8Array(15)), "CT_RANGE");
        expectRangeError(() => encodeFrameRequest(aad, new Uint8Array(32_785)), "CT_RANGE");
        expectRangeError(() => encodeFrameRequest(aad, forced(Array(16).fill(0))), "CT_RANGE");
        expect(cbor.encodeCanonical).not.toHaveBeenCalled();
    });

    it("the enroll plaintext needs no range checks and is encoded", () => {
        encodeOpenPlaintext({ op: "enroll" });
        expect(cbor.encodeCanonical).toHaveBeenCalledOnce();
    });
});

const ENVELOPE_LIMITS = { maxBytes: 65_536, maxDepth: 2, maxItems: 16 };
const AAD_LIMITS = { maxBytes: 512, maxDepth: 2, maxItems: 16 };
const CT = new Uint8Array(16).fill(6);

const cborMap = (entries: Record<string, CanonicalValue>): Uint8Array =>
    cbor.encodeCanonical(new Map(Object.entries(entries)));
const openResultAad = (over: Record<string, CanonicalValue> = {}): Uint8Array =>
    cborMap({ session_id: SID, request_id: RID, seq: 0, ...over });
const frameResultAad = (over: Record<string, CanonicalValue> = {}): Uint8Array =>
    cborMap({ session_id: SID, seq: 3, op: "test.echo", ...over });
const response = (entries: Record<string, CanonicalValue>): Uint8Array => cborMap(entries);

describe("criterion 3: decodeResponse returns the typed envelope", () => {
    it("decodes an open_result with a session id, keeping the nested aad bytes", () => {
        const aad = openResultAad();
        const got = decodeResponse(
            response({ kind: "open_result", aad, ct: CT }),
            ENVELOPE_LIMITS,
            AAD_LIMITS,
        );
        expect(got).toEqual({
            kind: "open_result",
            aadBytes: aad,
            aad: { sessionId: SID, requestId: RID },
            ct: CT,
        });
    });

    it("decodes an open_result refusal with a nil session id", () => {
        const aad = openResultAad({ session_id: null });
        const got = decodeResponse(
            response({ kind: "open_result", aad, ct: CT }),
            ENVELOPE_LIMITS,
            AAD_LIMITS,
        );
        expect(got).toEqual({
            kind: "open_result",
            aadBytes: aad,
            aad: { sessionId: null, requestId: RID },
            ct: CT,
        });
    });

    it("decodes a frame_result at the CDDL bounds (seq 2^53-1, ct 32784 bytes)", () => {
        const aad = frameResultAad({ seq: 2 ** 53 - 1 });
        const ct = new Uint8Array(32_784).fill(1);
        const got = decodeResponse(
            response({ kind: "frame_result", aad, ct }),
            ENVELOPE_LIMITS,
            AAD_LIMITS,
        );
        expect(got).toEqual({
            kind: "frame_result",
            aadBytes: aad,
            aad: { sessionId: SID, seq: 2 ** 53 - 1, op: "test.echo" },
            ct,
        });
    });

    it("decodes the envelope with the envelope limits and the aad with the aad limits", () => {
        const aad = frameResultAad();
        decodeResponse(
            response({ kind: "frame_result", aad, ct: CT }),
            ENVELOPE_LIMITS,
            AAD_LIMITS,
        );
        const calls = vi.mocked(cbor.decodeCanonical).mock.calls;
        expect(calls).toHaveLength(2);
        expect(calls[0]?.[1]).toBe(ENVELOPE_LIMITS);
        expect(calls[1]?.[0]).toEqual(aad);
        expect(calls[1]?.[1]).toBe(AAD_LIMITS);
    });
});

function expectWireError(fn: () => unknown, code: WireErrorCode): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    expect(thrown).toBeInstanceOf(WireError);
    expect((thrown as WireError).code).toBe(code);
}

describe("criterion 4: decodeResponse rejects schema violations with WireError (SR-3)", () => {
    const decode = (body: Uint8Array): unknown => decodeResponse(body, ENVELOPE_LIMITS, AAD_LIMITS);
    const openAad = openResultAad();
    const frameAad = frameResultAad();

    const malformed: readonly (readonly [string, () => Uint8Array])[] = [
        ["envelope is an array", () => cbor.encodeCanonical([1, 2])],
        ["envelope is an integer", () => cbor.encodeCanonical(1)],
        ["envelope is a byte string", () => cbor.encodeCanonical(openAad)],
        [
            "unknown envelope key",
            () => response({ kind: "open_result", aad: openAad, ct: CT, x: 1 }),
        ],
        ["missing ct", () => response({ kind: "open_result", aad: openAad })],
        ["missing aad", () => response({ kind: "frame_result", ct: CT })],
        ["missing kind", () => response({ aad: openAad, ct: CT })],
        ["kind open (a request)", () => response({ kind: "open", aad: openAad, ct: CT })],
        ["kind frame (a request)", () => response({ kind: "frame", aad: frameAad, ct: CT })],
        ["kind not text", () => response({ kind: 1, aad: openAad, ct: CT })],
        ["kind with different case", () => response({ kind: "Open_result", aad: openAad, ct: CT })],
        ["aad text", () => response({ kind: "open_result", aad: "text", ct: CT })],
        ["ct text", () => response({ kind: "open_result", aad: openAad, ct: "text" })],
        ["ct 15 bytes", () => response({ kind: "open_result", aad: openAad, ct: CT.subarray(1) })],
        [
            "ct 32785 bytes",
            () => response({ kind: "frame_result", aad: frameAad, ct: new Uint8Array(32_785) }),
        ],
        [
            "nested aad is an array",
            () => response({ kind: "open_result", aad: cbor.encodeCanonical([]), ct: CT }),
        ],
        [
            "open aad seq 1",
            () => response({ kind: "open_result", aad: openResultAad({ seq: 1 }), ct: CT }),
        ],
        [
            "open aad seq text",
            () => response({ kind: "open_result", aad: openResultAad({ seq: "0" }), ct: CT }),
        ],
        [
            "open aad seq -1",
            () => response({ kind: "open_result", aad: openResultAad({ seq: -1 }), ct: CT }),
        ],
        [
            "open aad session id 15 bytes",
            () =>
                response({
                    kind: "open_result",
                    aad: openResultAad({ session_id: RID.subarray(1) }),
                    ct: CT,
                }),
        ],
        [
            "open aad session id text",
            () =>
                response({ kind: "open_result", aad: openResultAad({ session_id: "x" }), ct: CT }),
        ],
        [
            "open aad session id false",
            () =>
                response({
                    kind: "open_result",
                    aad: openResultAad({ session_id: false }),
                    ct: CT,
                }),
        ],
        [
            "open aad request id 15 bytes",
            () =>
                response({
                    kind: "open_result",
                    aad: openResultAad({ request_id: RID.subarray(1) }),
                    ct: CT,
                }),
        ],
        [
            "open aad request id nil",
            () =>
                response({ kind: "open_result", aad: openResultAad({ request_id: null }), ct: CT }),
        ],
        [
            "open aad extra key",
            () =>
                response({ kind: "open_result", aad: openResultAad({ op: "test.echo" }), ct: CT }),
        ],
        [
            "open aad missing seq",
            () =>
                response({
                    kind: "open_result",
                    aad: cborMap({ session_id: SID, request_id: RID }),
                    ct: CT,
                }),
        ],
        [
            "open_result carrying a frame aad",
            () => response({ kind: "open_result", aad: frameAad, ct: CT }),
        ],
        [
            "frame_result carrying an open-result aad",
            () => response({ kind: "frame_result", aad: openAad, ct: CT }),
        ],
        [
            "frame aad seq 2^53 (decodes to bigint, R-1)",
            () =>
                response({ kind: "frame_result", aad: frameResultAad({ seq: 2n ** 53n }), ct: CT }),
        ],
        [
            "frame aad seq 2^64-1",
            () =>
                response({
                    kind: "frame_result",
                    aad: frameResultAad({ seq: 2n ** 64n - 1n }),
                    ct: CT,
                }),
        ],
        [
            "frame aad seq -1",
            () => response({ kind: "frame_result", aad: frameResultAad({ seq: -1 }), ct: CT }),
        ],
        [
            "frame aad session id nil",
            () =>
                response({
                    kind: "frame_result",
                    aad: frameResultAad({ session_id: null }),
                    ct: CT,
                }),
        ],
        [
            "frame aad session id 17 bytes",
            () =>
                response({
                    kind: "frame_result",
                    aad: frameResultAad({ session_id: new Uint8Array(17) }),
                    ct: CT,
                }),
        ],
        [
            "frame aad op uppercase",
            () => response({ kind: "frame_result", aad: frameResultAad({ op: "Test" }), ct: CT }),
        ],
        [
            "frame aad op empty",
            () => response({ kind: "frame_result", aad: frameResultAad({ op: "" }), ct: CT }),
        ],
        [
            "frame aad op bytes",
            () => response({ kind: "frame_result", aad: frameResultAad({ op: SID }), ct: CT }),
        ],
        [
            "frame aad extra key",
            () => response({ kind: "frame_result", aad: frameResultAad({ x: 1 }), ct: CT }),
        ],
        [
            "frame aad missing op",
            () =>
                response({
                    kind: "frame_result",
                    aad: cborMap({ session_id: SID, seq: 3 }),
                    ct: CT,
                }),
        ],
        ["garbage", () => new Uint8Array([0xff, 0xff])],
        ["empty body", () => new Uint8Array(0)],
        [
            "trailing byte",
            () => Uint8Array.of(...response({ kind: "open_result", aad: openAad, ct: CT }), 0),
        ],
    ];

    it.each(malformed)("%s → MALFORMED", (_name, make) => {
        expectWireError(() => decode(make()), "MALFORMED");
    });

    it("propagates the codec's error for a non-canonical nested aad", () => {
        // map(3) with keys "session_id", "seq", "request_id": canonical order is by encoded key bytes.
        const nonCanonical = Uint8Array.of(
            0xa3,
            ...cbor.encodeCanonical("session_id"),
            ...cbor.encodeCanonical(SID),
            ...cbor.encodeCanonical("seq"),
            0x00,
            ...cbor.encodeCanonical("request_id"),
            ...cbor.encodeCanonical(RID),
        );
        expectWireError(
            () => decode(response({ kind: "open_result", aad: nonCanonical, ct: CT })),
            "NONCANONICAL",
        );
    });

    it("propagates the codec's error for a non-canonical envelope and an over-limit aad", () => {
        const nonShortest = Uint8Array.of(
            0xb8,
            0x03,
            ...response({ kind: "open_result", aad: openAad, ct: CT }).subarray(1),
        );
        expectWireError(() => decode(nonShortest), "NONCANONICAL");
        expectWireError(
            () =>
                decodeResponse(
                    response({ kind: "open_result", aad: openAad, ct: CT }),
                    ENVELOPE_LIMITS,
                    {
                        ...AAD_LIMITS,
                        maxBytes: openAad.length - 1,
                    },
                ),
            "TOO_LARGE",
        );
        expectWireError(
            () =>
                decodeResponse(
                    response({ kind: "open_result", aad: openAad, ct: CT }),
                    { ...ENVELOPE_LIMITS, maxBytes: 8 },
                    AAD_LIMITS,
                ),
            "TOO_LARGE",
        );
    });

    it("re-encodes the nested aad and requires byte equality with the received bytes", () => {
        const aad = frameResultAad();
        const decodeSpy = vi.mocked(cbor.decodeCanonical);
        const real = decodeSpy.getMockImplementation() as typeof cbor.decodeCanonical;
        decodeSpy.mockImplementationOnce(real).mockImplementationOnce(
            () =>
                new Map<string, CanonicalValue>([
                    ["session_id", SID],
                    ["seq", 4],
                    ["op", "test.echo"],
                ]),
        );
        expectWireError(() => decode(response({ kind: "frame_result", aad, ct: CT })), "MALFORMED");
    });
});

const PAYLOAD_LIMITS = { maxBytes: 32_768, maxDepth: 16, maxItems: 4096 };

function expectInvalidResponse(fn: () => unknown): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    expect(thrown).toBeInstanceOf(ChannelError);
    expect((thrown as ChannelError).code).toBe("INVALID_RESPONSE");
    expect((thrown as ChannelError).detail).toBeUndefined();
}

describe("criterion 5: decodeOpenResultPlaintext (SR-3, R-3)", () => {
    const accepted = { sessionId: SID, requestId: RID };
    const refused = { sessionId: null, requestId: RID };
    const payload = new Map<string, CanonicalValue>([
        ["client_id", CLIENT],
        ["n", [1, 2n ** 64n - 1n]],
    ]);

    it("decodes ok:true with a session id and keeps the payload", () => {
        expect(
            decodeOpenResultPlaintext(cborMap({ ok: true, payload }), accepted, PAYLOAD_LIMITS),
        ).toEqual({ ok: true, payload });
        expect(
            decodeOpenResultPlaintext(
                cborMap({ ok: true, payload: null }),
                accepted,
                PAYLOAD_LIMITS,
            ),
        ).toEqual({ ok: true, payload: null });
    });

    it("decodes ok:false with a nil session id, keeping any well-formed error code as received", () => {
        for (const error of ["INTERNAL", "X", "SOME_FUTURE_CODE_9", `A${"B".repeat(63)}`]) {
            expect(
                decodeOpenResultPlaintext(cborMap({ ok: false, error }), refused, PAYLOAD_LIMITS),
            ).toEqual({ ok: false, error });
        }
    });

    it("rejects ok:true with a nil session id and ok:false with a session id (R-3)", () => {
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(
                cborMap({ ok: true, payload: null }),
                refused,
                PAYLOAD_LIMITS,
            ),
        );
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(
                cborMap({ ok: false, error: "INTERNAL" }),
                accepted,
                PAYLOAD_LIMITS,
            ),
        );
    });

    const invalid: readonly (readonly [string, Record<string, CanonicalValue>])[] = [
        ["ok missing", { payload: null }],
        ["ok not boolean", { ok: 1, payload: null }],
        ["error lower case", { ok: false, error: "internal" }],
        ["error leading digit", { ok: false, error: "1NTERNAL" }],
        ["error empty", { ok: false, error: "" }],
        ["error 65 chars", { ok: false, error: `A${"B".repeat(64)}` }],
        ["error with newline", { ok: false, error: "INTERNAL\n" }],
        ["error not text", { ok: false, error: 3 }],
        ["payload missing on success", { ok: true }],
        ["error missing on failure", { ok: false }],
        ["payload on failure", { ok: false, payload: null }],
        ["error on success", { ok: true, error: "INTERNAL" }],
        ["extra key", { ok: true, payload: null, x: 1 }],
        ["error and payload together", { ok: false, error: "X", payload: null }],
    ];

    it.each(invalid)("rejects %s as INVALID_RESPONSE", (_name, body) => {
        const aad = body["ok"] === true ? accepted : refused;
        expectInvalidResponse(() => decodeOpenResultPlaintext(cborMap(body), aad, PAYLOAD_LIMITS));
    });

    it("rejects a plaintext that is not a map, not canonical CBOR, or over the limits", () => {
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(cbor.encodeCanonical([true]), refused, PAYLOAD_LIMITS),
        );
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(new Uint8Array([0xff]), refused, PAYLOAD_LIMITS),
        );
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(new Uint8Array(0), refused, PAYLOAD_LIMITS),
        );
        expectInvalidResponse(() =>
            decodeOpenResultPlaintext(cborMap({ ok: true, payload: "x".repeat(64) }), accepted, {
                ...PAYLOAD_LIMITS,
                maxBytes: 32,
            }),
        );
    });

    it("decodes the plaintext with the given limits", () => {
        decodeOpenResultPlaintext(cborMap({ ok: false, error: "X" }), refused, PAYLOAD_LIMITS);
        expect(cbor.decodeCanonical).toHaveBeenCalledWith(expect.any(Uint8Array), PAYLOAD_LIMITS);
    });
});

describe("criterion 6: decodeFrameResultPlaintext (SR-3, R-1)", () => {
    const decode = (body: Record<string, CanonicalValue>): unknown =>
        decodeFrameResultPlaintext(cborMap(body), PAYLOAD_LIMITS);

    it("decodes success and failure bodies, re at both bounds", () => {
        const payload = [new Uint8Array([1]), "x", null];
        expect(decode({ re: 4, ok: true, payload })).toEqual({ re: 4, ok: true, payload });
        expect(decode({ re: 0, ok: false, error: "NOT_AUTHORIZED" })).toEqual({
            re: 0,
            ok: false,
            error: "NOT_AUTHORIZED",
        });
        expect(decode({ re: 2 ** 53 - 1, ok: true, payload: null })).toEqual({
            re: 2 ** 53 - 1,
            ok: true,
            payload: null,
        });
    });

    const invalid: readonly (readonly [string, Record<string, CanonicalValue>])[] = [
        ["re missing (success)", { ok: true, payload: null }],
        ["re missing (failure)", { ok: false, error: "INTERNAL" }],
        ["re as bigint 2^53", { re: 2n ** 53n, ok: true, payload: null }],
        ["re negative", { re: -1, ok: true, payload: null }],
        ["re text", { re: "1", ok: true, payload: null }],
        ["re nil", { re: null, ok: false, error: "INTERNAL" }],
        ["ok missing", { re: 1, payload: null }],
        ["ok not boolean", { re: 1, ok: 0, payload: null }],
        ["error lower case", { re: 1, ok: false, error: "lower" }],
        ["error too long", { re: 1, ok: false, error: `A${"B".repeat(64)}` }],
        ["payload on failure", { re: 1, ok: false, payload: null }],
        ["error on success", { re: 1, ok: true, error: "INTERNAL" }],
        ["extra key (success)", { re: 1, ok: true, payload: null, x: 1 }],
        ["extra key (failure)", { re: 1, ok: false, error: "INTERNAL", x: 1 }],
        ["error and payload together", { re: 1, ok: false, error: "X", payload: null }],
    ];

    it.each(invalid)("rejects %s as INVALID_RESPONSE", (_name, body) => {
        expectInvalidResponse(() => decode(body));
    });

    it("rejects a plaintext that is not a map, not CBOR, or over the limits", () => {
        expectInvalidResponse(() =>
            decodeFrameResultPlaintext(cbor.encodeCanonical(1), PAYLOAD_LIMITS),
        );
        expectInvalidResponse(() =>
            decodeFrameResultPlaintext(new Uint8Array([0xff]), PAYLOAD_LIMITS),
        );
        expectInvalidResponse(() =>
            decodeFrameResultPlaintext(cborMap({ re: 1, ok: true, payload: [[[1]]] }), {
                ...PAYLOAD_LIMITS,
                maxDepth: 3,
            }),
        );
    });
});
