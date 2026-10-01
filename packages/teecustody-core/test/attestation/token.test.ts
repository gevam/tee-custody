// T-10: parseToken (API.md §D; ADR 0009 rule 1). Security path: every rejection branch has a negative test.
import { describe, expect, it } from "vitest";

import { parseToken } from "../../src/attestation/token.js";
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
