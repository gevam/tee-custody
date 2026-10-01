// T-10: parseToken (API.md §D; ADR 0009 rule 1). Security path: every rejection branch has a negative test.
import { describe, expect, it } from "vitest";

import { parseToken } from "../../src/attestation/token.js";
import { AttestationError } from "../../src/attestation/types.js";
import { generateRsaKey, signJws } from "../support/jws.js";
import {
    RFC7515_A2_COMPACT,
    RFC7515_A2_HEADER_OCTETS,
    RFC7515_A2_PAYLOAD_OCTETS,
} from "../support/rfc7515.js";

const MAX = 16_384;
const ascii = new TextEncoder();

describe("parseToken accepts a well-formed compact JWS", () => {
    it("returns header, claims, signature bytes and the exact signing input", async () => {
        const { privateKey } = await generateRsaKey();
        const header = { alg: "RS256", kid: "k1", typ: "JWT" };
        const claims = { iss: "https://issuer.unit.test", exp: 1, nested: { a: [1, "b"] } };
        const token = await signJws(header, claims, privateKey);
        const [seg1 = "", seg2 = "", seg3 = ""] = token.split(".");

        const parsed = parseToken(token, MAX);

        expect(parsed.header).toEqual(header);
        expect(parsed.claims).toEqual(claims);
        expect(parsed.signingInput).toEqual(ascii.encode(`${seg1}.${seg2}`));
        expect(parsed.signature).toEqual(new Uint8Array(Buffer.from(seg3, "base64url")));
        expect(parsed.signature).toHaveLength(256);
    });

    it("reproduces the RFC 7515 A.2 signing input byte for byte (ADR 0009 KAT)", () => {
        const parsed = parseToken(RFC7515_A2_COMPACT, MAX);
        const headerB64 = Buffer.from(RFC7515_A2_HEADER_OCTETS).toString("base64url");
        const payloadB64 = Buffer.from(RFC7515_A2_PAYLOAD_OCTETS).toString("base64url");

        expect(parsed.signingInput).toEqual(ascii.encode(`${headerB64}.${payloadB64}`));
        expect(parsed.header).toEqual({ alg: "RS256" });
        expect(parsed.claims).toEqual({
            iss: "joe",
            exp: 1300819380,
            "http://example.com/is_root": true,
        });
        expect(parsed.signature).toHaveLength(256);
    });
});

function b64url(text: string): string {
    return Buffer.from(text, "utf8").toString("base64url");
}

const HEADER = b64url('{"alg":"RS256","kid":"k1"}');
const CLAIMS = b64url('{"iss":"https://issuer.unit.test"}');
const SIGNATURE = Buffer.from([1, 2, 3]).toString("base64url");
const GOOD = `${HEADER}.${CLAIMS}.${SIGNATURE}`;
const INVALID_UTF8 = Buffer.from([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x3a, 0x31, 0x7d]).toString(
    "base64url",
);

function malformed(token: string, maxTokenBytes = MAX): AttestationError {
    try {
        parseToken(token, maxTokenBytes);
    } catch (error) {
        if (error instanceof AttestationError) {
            return error;
        }
        throw error;
    }
    throw new Error("expected parseToken to throw");
}

describe("parseToken rejects malformed tokens with MALFORMED/token and no token text (SR-3, SR-11)", () => {
    const cases: readonly (readonly [string, string, number] | readonly [string, string])[] = [
        ["one byte over maxTokenBytes", GOOD, ascii.encode(GOOD).length - 1],
        ["two segments", `${HEADER}.${CLAIMS}`],
        ["four segments", `${GOOD}.${SIGNATURE}`],
        ["empty header segment", `.${CLAIMS}.${SIGNATURE}`],
        ["empty payload segment", `${HEADER}..${SIGNATURE}`],
        ["= padding", `${HEADER}.${CLAIMS}.${b64url("ab")}==`],
        ["standard-alphabet character", `${HEADER}+.${CLAIMS}.${SIGNATURE}`],
        ["non-JSON header", `${b64url("not json")}.${CLAIMS}.${SIGNATURE}`],
        ["JSON array payload", `${HEADER}.${b64url("[1,2]")}.${SIGNATURE}`],
        ["JSON null header", `${b64url("null")}.${CLAIMS}.${SIGNATURE}`],
        ["JSON string payload", `${HEADER}.${b64url('"x"')}.${SIGNATURE}`],
        ["invalid UTF-8 header", `${INVALID_UTF8}.${CLAIMS}.${SIGNATURE}`],
        ["non-zero unused base64url bits", `${HEADER}.${CLAIMS}.AB`],
        ["segment length ≡ 1 mod 4", `${HEADER}.${CLAIMS}.ABCDE`],
        ["non-ASCII character", `${HEADER}.${CLAIMS}.é`],
    ];

    it.each(cases)("%s", (_name, token, maxTokenBytes = MAX) => {
        const error = malformed(token, maxTokenBytes);
        expect([error.code, error.check]).toEqual(["MALFORMED", "token"]);
        expect(error.message).toBe("token: MALFORMED");
        expect(error.cause).toBeUndefined();
    });

    it("accepts a token exactly maxTokenBytes long", () => {
        expect(parseToken(GOOD, ascii.encode(GOOD).length).signature).toEqual(
            new Uint8Array([1, 2, 3]),
        );
    });

    it("accepts an empty signature segment so checkSignature classifies alg none", () => {
        expect(parseToken(`${HEADER}.${CLAIMS}.`, MAX).signature).toEqual(new Uint8Array(0));
    });

    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53])(
        "rejects maxTokenBytes %s",
        (maxTokenBytes) => {
            const error = malformed(GOOD, maxTokenBytes);
            expect([error.code, error.check]).toEqual(["MALFORMED", "token"]);
        },
    );

    it("rejects a non-string token from an untyped caller", () => {
        const error = malformed(42 as unknown as string);
        expect([error.code, error.check]).toEqual(["MALFORMED", "token"]);
    });
});
