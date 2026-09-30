// Test-only RS256 JWS helpers over WebCrypto (API.md §D; ADR 0009). Keys are generated per test run.
import type { RsaPublicJwk } from "../../src/capabilities.js";

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

function base64UrlOf(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

export async function generateRsaKey(
    modulusLength = 2048,
): Promise<{ privateKey: CryptoKey; jwk: RsaPublicJwk }> {
    const pair = await subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    );
    const { n, e } = await subtle.exportKey("jwk", pair.publicKey);
    if (n === undefined || e === undefined) {
        throw new Error("RSA JWK export lacks n or e");
    }
    return { privateKey: pair.privateKey, jwk: { kty: "RSA", n, e } };
}

export async function signJws(header: object, claims: object, key: CryptoKey): Promise<string> {
    const signingInput = [header, claims]
        .map((part) => base64UrlOf(encoder.encode(JSON.stringify(part))))
        .join(".");
    const signature = await subtle.sign("RSASSA-PKCS1-v1_5", key, encoder.encode(signingInput));
    return `${signingInput}.${base64UrlOf(new Uint8Array(signature))}`;
}
