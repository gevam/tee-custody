// createWebCrypto (INC-2-API §8.1; T-17 criteria 1–3, 6; ADR 0011).
import { CapabilityError, type PublicKeyInput } from "@teecustody/core";
import { describe, expect, it } from "vitest";

import { createWebCrypto } from "../../src/crypto/webcrypto.js";

const enc = new TextEncoder();
const MSG = enc.encode("signed message");

async function codeOfRejection(promise: Promise<unknown>): Promise<string> {
    try {
        await promise;
    } catch (error: unknown) {
        return error instanceof CapabilityError ? error.code : `not a CapabilityError: ${String(error)}`;
    }
    return "no error";
}

/** The real SubtleCrypto with `importKey` replaced for algorithms named in `refuse`. */
function refusingImport(refuse: string, error: () => unknown): SubtleCrypto {
    const real = globalThis.crypto.subtle;
    return new Proxy(real, {
        get(target, prop) {
            const value = Reflect.get(target, prop, target) as unknown;
            if (prop !== "importKey" || typeof value !== "function") {
                return typeof value === "function" ? value.bind(target) : value;
            }
            return (...args: Parameters<SubtleCrypto["importKey"]>) => {
                const algorithm = args[2];
                const name = typeof algorithm === "string" ? algorithm : algorithm.name;
                if (name === refuse) {
                    return Promise.reject(error());
                }
                return target.importKey(...args);
            };
        },
    });
}

async function ed25519KeyPair(): Promise<{ publicKey: Uint8Array; sign: (m: Uint8Array) => Promise<Uint8Array> }> {
    const subtle = globalThis.crypto.subtle;
    const pair = (await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    return {
        publicKey,
        sign: async (m) => new Uint8Array(await subtle.sign({ name: "Ed25519" }, pair.privateKey, m)),
    };
}

const RS256: RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

async function rsaSigner(modulusLength: number): Promise<{
    key: PublicKeyInput;
    sign: (m: Uint8Array) => Promise<Uint8Array>;
}> {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey(
        { ...RS256, modulusLength, publicExponent: new Uint8Array([1, 0, 1]) },
        true,
        ["sign", "verify"],
    );
    const jwk = await subtle.exportKey("jwk", pair.publicKey);
    return {
        key: { format: "jwk", jwk: { kty: "RSA", n: jwk.n ?? "", e: jwk.e ?? "" } },
        sign: async (m) => new Uint8Array(await subtle.sign(RS256.name, pair.privateKey, m)),
    };
}

function codeOfThrown(fn: () => unknown): string {
    try {
        fn();
    } catch (error: unknown) {
        return error instanceof CapabilityError ? error.code : `not a CapabilityError: ${String(error)}`;
    }
    return "no error";
}

describe("randomBytes (criterion 1)", () => {
    it("rejects lengths outside 1..65536 with INVALID_ARGUMENT", () => {
        const crypto = createWebCrypto();
        expect(codeOfThrown(() => crypto.randomBytes(0))).toBe("INVALID_ARGUMENT");
        expect(codeOfThrown(() => crypto.randomBytes(65537))).toBe("INVALID_ARGUMENT");
    });

    it("returns n fresh random bytes on each call", () => {
        const crypto = createWebCrypto();
        const a = crypto.randomBytes(32);
        const b = crypto.randomBytes(32);
        expect(a).toHaveLength(32);
        expect(b).toHaveLength(32);
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    });
});

describe("verifyEd25519 (criterion 2)", () => {
    it("returns true for a valid signature and false for a bit-flipped one", async () => {
        const crypto = createWebCrypto();
        const { publicKey, sign } = await ed25519KeyPair();
        const signature = await sign(MSG);
        expect(await crypto.verifyEd25519(publicKey, MSG, signature)).toBe(true);
        const flipped = signature.slice();
        flipped[10] = (flipped[10] ?? 0) ^ 0x01;
        expect(await crypto.verifyEd25519(publicKey, MSG, flipped)).toBe(false);
    });

    it("rejects a 31-byte key or a 63-byte signature with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { publicKey, sign } = await ed25519KeyPair();
        const signature = await sign(MSG);
        expect(await codeOfRejection(crypto.verifyEd25519(publicKey.slice(0, 31), MSG, signature))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(await codeOfRejection(crypto.verifyEd25519(publicKey, MSG, signature.slice(0, 63)))).toBe(
            "INVALID_ARGUMENT",
        );
    });

    it("reports UNSUPPORTED when the subtle's Ed25519 import throws NotSupportedError", async () => {
        const subtle = refusingImport("Ed25519", () => new DOMException("no Ed25519", "NotSupportedError"));
        const crypto = createWebCrypto({ subtle });
        const { publicKey, sign } = await ed25519KeyPair();
        expect(await codeOfRejection(crypto.verifyEd25519(publicKey, MSG, await sign(MSG)))).toBe(
            "UNSUPPORTED",
        );
    });
});

describe("verifySignature (criterion 3, B-06)", () => {
    it("rejects a 1024-bit RS256 key with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { key, sign } = await rsaSigner(1024);
        const signature = await sign(MSG);
        expect(
            await codeOfRejection(crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, MSG, signature)),
        ).toBe("INVALID_ARGUMENT");
    });

    it("accepts a valid 2048-bit RS256 signature", async () => {
        const crypto = createWebCrypto();
        const { key, sign } = await rsaSigner(2048);
        const signature = await sign(MSG);
        expect(await crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, MSG, signature)).toBe(true);
    });
});
