// T-15: Core channel wire codec (INC-2-API §2, §3.1, §7.3; API-TL §3; SR-3, SR-14).
// Expected bytes are hex literals computed independently with the Python canonical codec.
import { describe, expect, it } from "vitest";

import {
    encodeFrameAad,
    encodeFrameRequest,
    encodeOpenAad,
    encodeOpenPlaintext,
    encodeOpenRequest,
} from "../../src/channel/wire.js";

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
