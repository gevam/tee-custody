import { describe, expect, it } from "vitest";

import { EncodingError, base64Decode, base64UrlDecode } from "../src/encoding.js";

describe("base64Decode (RFC 4648 §4, strict)", () => {
    it("decodes padded standard base64", () => {
        expect([...base64Decode("AQID")]).toEqual([1, 2, 3]);
        expect([...base64Decode("AQI=")]).toEqual([1, 2]);
        expect([...base64Decode("AQ==")]).toEqual([1]);
        expect([...base64Decode("+/8=")]).toEqual([0xfb, 0xff]);
        expect([...base64Decode("")]).toEqual([]);
    });

    it.each([
        ["missing padding", "AQI"],
        ["url alphabet -", "-_8="],
        ["url alphabet _", "AQ_="],
        ["whitespace", "AQ ID"],
        ["newline", "AQID\n"],
        ["non-zero trailing bits", "AR=="],
        ["non-zero trailing bits, one pad", "AQJ="],
        ["too much padding", "A==="],
        ["padding in the middle", "AQ==AQID"],
        ["length not a multiple of 4", "AQIDA"],
    ])("rejects %s", (_name, input) => {
        expect(() => base64Decode(input)).toThrow(EncodingError);
    });
});

describe("base64UrlDecode (RFC 4648 §5, unpadded, canonical)", () => {
    it("decodes unpadded base64url", () => {
        expect([...base64UrlDecode("AQI")]).toEqual([1, 2]);
        expect([...base64UrlDecode("AQID")]).toEqual([1, 2, 3]);
        expect([...base64UrlDecode("AQ")]).toEqual([1]);
        expect([...base64UrlDecode("-_8")]).toEqual([0xfb, 0xff]);
        expect([...base64UrlDecode("")]).toEqual([]);
    });

    it.each([
        ["padding", "AQI="],
        ["standard alphabet +", "+_8"],
        ["standard alphabet /", "-/8"],
        ["whitespace", "AQ I"],
        ["newline", "AQI\n"],
        ["non-zero unused bits (2 chars)", "AR"],
        ["non-zero unused bits (3 chars)", "AQJ"],
        ["length ≡ 1 (mod 4)", "AQIDA"],
        ["single character", "A"],
        ["non-ASCII", "AQé"],
    ])("rejects %s", (_name, input) => {
        expect(() => base64UrlDecode(input)).toThrow(EncodingError);
    });
});
