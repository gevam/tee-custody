import { describe, expect, it } from "vitest";

import { CapabilityError } from "../src/capabilities.js";
import {
    EncodingError,
    base64Decode,
    base64UrlDecode,
    hexEncode,
    utf8DecodeStrict,
    utf8Encode,
} from "../src/encoding.js";
import { mapFetcher } from "./support/fetcher.js";
import { generateRsaKey, signJws } from "./support/jws.js";
import {
    RFC7515_A2_COMPACT,
    RFC7515_A2_HEADER_OCTETS,
    RFC7515_A2_PAYLOAD_OCTETS,
    RFC7515_A2_PRIVATE_JWK,
    RFC7515_A2_PUBLIC_JWK,
} from "./support/rfc7515.js";
import { testCrypto } from "./support/webcrypto.js";

const RS256 = "RSASSA_PKCS1V15_SHA256";
const ascii = new TextEncoder();

function splitCompact(token: string): { signingInput: Uint8Array; signature: Uint8Array } {
    const [header = "", payload = "", signature = ""] = token.split(".");
    return {
        signingInput: ascii.encode(`${header}.${payload}`),
        signature: base64UrlDecode(signature),
    };
}

async function capabilityCode(outcome: Promise<unknown>): Promise<string> {
    try {
        await outcome;
    } catch (error) {
        if (error instanceof CapabilityError) {
            return error.code;
        }
        throw error;
    }
    throw new Error("expected a CapabilityError");
}

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
        ["padding only", "===="],
        ["a full quantum followed by padding only", "AAAA===="],
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

describe("utf8DecodeStrict, utf8Encode, hexEncode", () => {
    it.each([
        ["an invalid continuation", [0xc3, 0x28]],
        ["an overlong encoding", [0xc0, 0x80]],
        ["a UTF-16 surrogate", [0xed, 0xa0, 0x80]],
        ["a truncated sequence", [0xe2, 0x82]],
    ])("rejects %s", (_name, bytes) => {
        expect(() => utf8DecodeStrict(new Uint8Array(bytes))).toThrow(EncodingError);
    });

    it("decodes valid UTF-8 and keeps a leading BOM", () => {
        expect(utf8DecodeStrict(new Uint8Array([0xe2, 0x82, 0xac]))).toBe("€");
        expect(utf8DecodeStrict(new Uint8Array([0xef, 0xbb, 0xbf, 0x61]))).toBe("\ufeffa");
    });

    it("encodes UTF-8", () => {
        expect([...utf8Encode("é€")]).toEqual([0xc3, 0xa9, 0xe2, 0x82, 0xac]);
    });

    it("hex-encodes in lowercase", () => {
        expect(hexEncode(new Uint8Array([0, 255]))).toBe("00ff");
        expect(hexEncode(new Uint8Array([0x0a, 0xbc]))).toBe("0abc");
        expect(hexEncode(new Uint8Array())).toBe("");
    });
});

describe("RFC 7515 A.2 known answer (ADR 0009) through testCrypto", () => {
    it("decodes the A.2 header and payload octets from the compact serialization", () => {
        const [header = "", payload = ""] = RFC7515_A2_COMPACT.split(".");
        expect(base64UrlDecode(header)).toEqual(RFC7515_A2_HEADER_OCTETS);
        expect(base64UrlDecode(payload)).toEqual(RFC7515_A2_PAYLOAD_OCTETS);
    });

    it("verifies the A.2 signature with the A.2 public JWK", async () => {
        const { signingInput, signature } = splitCompact(RFC7515_A2_COMPACT);
        const key = { format: "jwk", jwk: RFC7515_A2_PUBLIC_JWK } as const;
        await expect(
            testCrypto().verifySignature(RS256, key, signingInput, signature),
        ).resolves.toBe(true);
    });

    it("rejects the A.2 signature after a one-bit flip", async () => {
        const { signingInput, signature } = splitCompact(RFC7515_A2_COMPACT);
        signature[17] = (signature[17] ?? 0) ^ 0x01;
        const key = { format: "jwk", jwk: RFC7515_A2_PUBLIC_JWK } as const;
        await expect(
            testCrypto().verifySignature(RS256, key, signingInput, signature),
        ).resolves.toBe(false);
    });

    it("reproduces the A.2 signature from the transcribed private JWK", async () => {
        const { signingInput, signature } = splitCompact(RFC7515_A2_COMPACT);
        const privateKey = await globalThis.crypto.subtle.importKey(
            "jwk",
            RFC7515_A2_PRIVATE_JWK,
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["sign"],
        );
        const produced = await globalThis.crypto.subtle.sign(
            "RSASSA-PKCS1-v1_5",
            privateKey,
            signingInput.slice(),
        );
        expect(new Uint8Array(produced)).toEqual(signature);
    });

    it("rejects a 1024-bit key with INVALID_ARGUMENT", async () => {
        const { privateKey, jwk } = await generateRsaKey(1024);
        const token = await signJws({ alg: "RS256" }, { iss: "x" }, privateKey);
        const { signingInput, signature } = splitCompact(token);
        const key = { format: "jwk", jwk } as const;
        expect(
            await capabilityCode(testCrypto().verifySignature(RS256, key, signingInput, signature)),
        ).toBe("INVALID_ARGUMENT");
    });

    it("rejects an unparseable key with INVALID_ARGUMENT", async () => {
        const key = { format: "jwk", jwk: { kty: "RSA", n: "!", e: "AQAB" } } as const;
        expect(
            await capabilityCode(
                testCrypto().verifySignature(RS256, key, new Uint8Array(1), new Uint8Array(1)),
            ),
        ).toBe("INVALID_ARGUMENT");
    });

    it("rejects any other algorithm with UNSUPPORTED_ALGORITHM", async () => {
        const key = { format: "jwk", jwk: RFC7515_A2_PUBLIC_JWK } as const;
        const algorithm = "RSASSA_PSS_SHA256" as unknown as typeof RS256;
        expect(
            await capabilityCode(
                testCrypto().verifySignature(algorithm, key, new Uint8Array(1), new Uint8Array(1)),
            ),
        ).toBe("UNSUPPORTED_ALGORITHM");
    });

    it("verifies a token made by signJws with a default 2048-bit generateRsaKey key", async () => {
        const { privateKey, jwk } = await generateRsaKey();
        const token = await signJws({ alg: "RS256", kid: "k" }, { iss: "x", n: 1 }, privateKey);
        const [header = "", payload = ""] = token.split(".");
        expect(JSON.parse(new TextDecoder().decode(base64UrlDecode(header)))).toEqual({
            alg: "RS256",
            kid: "k",
        });
        expect(JSON.parse(new TextDecoder().decode(base64UrlDecode(payload)))).toEqual({
            iss: "x",
            n: 1,
        });
        const { signingInput, signature } = splitCompact(token);
        expect(jwk.kty).toBe("RSA");
        expect(jwk.e).toBe("AQAB");
        expect(base64UrlDecode(jwk.n)).toHaveLength(256);
        await expect(
            testCrypto().verifySignature(RS256, { format: "jwk", jwk }, signingInput, signature),
        ).resolves.toBe(true);
    });

    it("hashes with SHA-256", async () => {
        const digest = await testCrypto().sha256(ascii.encode("abc"));
        expect(Buffer.from(digest).toString("hex")).toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    });
});

describe("mapFetcher (test support)", () => {
    const url = "https://issuer.unit.test/jwks";
    const body = new Uint8Array([1, 2, 3]);

    it("serves the exact URL with status 200 by default", async () => {
        const response = await mapFetcher(new Map([[url, body]])).get(url);
        expect(response.status).toBe(200);
        expect(response.body).toEqual(body);
    });

    it("uses the configured status for a URL", async () => {
        const fetcher = mapFetcher(new Map([[url, body]]), new Map([[url, 404]]));
        expect((await fetcher.get(url)).status).toBe(404);
    });

    it("rejects any other URL with HTTP_ERROR", async () => {
        const fetcher = mapFetcher(new Map([[url, body]]));
        expect(await capabilityCode(fetcher.get(`${url}/`))).toBe("HTTP_ERROR");
    });
});
