// T-15: Core channel wire codec (INC-2-API §2, §3.1, §7.3; API-TL §3; SR-3, SR-14).
// Expected bytes are hex literals computed independently with the Python canonical codec.
import { afterEach, describe, expect, it, vi } from "vitest";

import * as cbor from "../../src/wire/cbor.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import {
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
