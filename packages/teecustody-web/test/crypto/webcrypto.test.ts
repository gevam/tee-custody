// createWebCrypto (INC-2-API §8.1; T-17 criteria 1–3, 6; ADR 0011).
import { CapabilityError, type PublicKeyInput } from "@teecustody/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createWebCrypto } from "../../src/crypto/webcrypto.js";

const enc = new TextEncoder();
const MSG = enc.encode("signed message");

async function codeOfRejection(promise: Promise<unknown>): Promise<string> {
    try {
        await promise;
    } catch (error: unknown) {
        return error instanceof CapabilityError
            ? error.code
            : `not a CapabilityError: ${String(error)}`;
    }
    return "no error";
}

/** The real SubtleCrypto with `importKey` replaced for the algorithm named `refuse`. */
function refusingImport(refuse: string, failure: () => Error): SubtleCrypto {
    const real = globalThis.crypto.subtle;
    const realImport = real.importKey.bind(real) as (...args: unknown[]) => Promise<CryptoKey>;
    const importKey = (...args: unknown[]): Promise<CryptoKey> => {
        const algorithm = args[2] as AlgorithmIdentifier;
        const name = typeof algorithm === "string" ? algorithm : algorithm.name;
        if (name === refuse) {
            return Promise.reject(failure());
        }
        return realImport(...args);
    };
    return new Proxy(real, {
        get(target, prop): unknown {
            if (prop === "importKey") {
                return importKey;
            }
            const value: unknown = Reflect.get(target, prop, target);
            return typeof value === "function" ? (value as () => unknown).bind(target) : value;
        },
    });
}

async function ed25519KeyPair(): Promise<{
    publicKey: Uint8Array;
    sign: (m: Uint8Array) => Promise<Uint8Array>;
}> {
    const subtle = globalThis.crypto.subtle;
    const pair = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const publicKey = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    return {
        publicKey,
        sign: async (m) =>
            new Uint8Array(await subtle.sign({ name: "Ed25519" }, pair.privateKey, m.slice())),
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
        sign: async (m) =>
            new Uint8Array(await subtle.sign(RS256.name, pair.privateKey, m.slice())),
    };
}

function codeOfThrown(fn: () => unknown): string {
    try {
        fn();
    } catch (error: unknown) {
        return error instanceof CapabilityError
            ? error.code
            : `not a CapabilityError: ${String(error)}`;
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
        expect(
            await codeOfRejection(crypto.verifyEd25519(publicKey.slice(0, 31), MSG, signature)),
        ).toBe("INVALID_ARGUMENT");
        expect(
            await codeOfRejection(crypto.verifyEd25519(publicKey, MSG, signature.slice(0, 63))),
        ).toBe("INVALID_ARGUMENT");
    });

    it("checks both lengths before any WebCrypto call", async () => {
        const importKey = vi.spyOn(globalThis.crypto.subtle, "importKey");
        const crypto = createWebCrypto();
        for (const [pk, sig] of [
            [new Uint8Array(31), new Uint8Array(64)],
            [new Uint8Array(33), new Uint8Array(64)],
            [new Uint8Array(32), new Uint8Array(65)],
        ] as const) {
            expect(await codeOfRejection(crypto.verifyEd25519(pk, MSG, sig))).toBe(
                "INVALID_ARGUMENT",
            );
        }
        expect(importKey).not.toHaveBeenCalled();
        importKey.mockRestore();
    });

    it("reports UNSUPPORTED when the subtle's Ed25519 import throws NotSupportedError", async () => {
        const subtle = refusingImport(
            "Ed25519",
            () => new DOMException("no Ed25519", "NotSupportedError"),
        );
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
            await codeOfRejection(
                crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, MSG, signature),
            ),
        ).toBe("INVALID_ARGUMENT");
    });

    it("accepts a valid 2048-bit RS256 signature", async () => {
        const crypto = createWebCrypto();
        const { key, sign } = await rsaSigner(2048);
        const signature = await sign(MSG);
        expect(await crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, MSG, signature)).toBe(
            true,
        );
    });
});

describe("aes256GcmEncrypt / aes256GcmDecrypt (criterion 6)", () => {
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(12).fill(9);
    const aad = enc.encode("aad");
    const plaintext = enc.encode("seventeen bytes!!");

    it("rejects a 31-byte key or an 11-byte nonce with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        for (const call of [
            () => crypto.aes256GcmEncrypt(key.slice(0, 31), nonce, aad, plaintext),
            () => crypto.aes256GcmEncrypt(key, nonce.slice(0, 11), aad, plaintext),
            () => crypto.aes256GcmDecrypt(key.slice(0, 31), nonce, aad, plaintext),
            () => crypto.aes256GcmDecrypt(key, nonce.slice(0, 11), aad, plaintext),
        ]) {
            expect(await codeOfRejection(call())).toBe("INVALID_ARGUMENT");
        }
    });

    it("outputs ct || 16-byte tag that decrypts back to the plaintext", async () => {
        const crypto = createWebCrypto();
        const sealed = await crypto.aes256GcmEncrypt(key, nonce, aad, plaintext);
        expect(sealed).toHaveLength(plaintext.length + 16);
        expect(Array.from(await crypto.aes256GcmDecrypt(key, nonce, aad, sealed))).toEqual(
            Array.from(plaintext),
        );
    });

    it("rejects a flipped tag bit with AUTHENTICATION_FAILED", async () => {
        const crypto = createWebCrypto();
        const sealed = await crypto.aes256GcmEncrypt(key, nonce, aad, plaintext);
        const flipped = sealed.slice();
        const last = flipped.length - 1;
        flipped[last] = (flipped[last] ?? 0) ^ 0x80;
        expect(await codeOfRejection(crypto.aes256GcmDecrypt(key, nonce, aad, flipped))).toBe(
            "AUTHENTICATION_FAILED",
        );
    });
});

describe("edge cases of the non-HPKE primitives", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("rejects non-integer and negative randomBytes lengths and accepts both bounds", () => {
        const crypto = createWebCrypto();
        for (const n of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
            expect(codeOfThrown(() => crypto.randomBytes(n))).toBe("INVALID_ARGUMENT");
        }
        expect(crypto.randomBytes(1)).toHaveLength(1);
        expect(crypto.randomBytes(65536)).toHaveLength(65536);
    });

    it("draws randomness from options.getRandomValues when given", () => {
        const getRandomValues = vi.fn((a: Uint8Array) => a.fill(0xab));
        const crypto = createWebCrypto({ getRandomValues });
        expect(Array.from(crypto.randomBytes(3))).toEqual([0xab, 0xab, 0xab]);
        expect(getRandomValues).toHaveBeenCalledTimes(1);
    });

    it("computes SHA-256 with subtle.digest", async () => {
        const digest = vi.spyOn(globalThis.crypto.subtle, "digest");
        const crypto = createWebCrypto();
        const out = await crypto.sha256(enc.encode("abc"));
        expect(Buffer.from(out).toString("hex")).toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        expect(digest).toHaveBeenCalledTimes(1);
        digest.mockRestore();
    });

    it("maps an Ed25519 import failure other than NotSupportedError to INVALID_ARGUMENT", async () => {
        for (const failure of [new DOMException("bad key", "DataError"), new TypeError("bad")]) {
            const crypto = createWebCrypto({ subtle: refusingImport("Ed25519", () => failure) });
            const error = await crypto
                .verifyEd25519(new Uint8Array(32), MSG, new Uint8Array(64))
                .catch((e: unknown) => e);
            expect(error).toBeInstanceOf(CapabilityError);
            expect((error as CapabilityError).code).toBe("INVALID_ARGUMENT");
            expect((error as CapabilityError).cause).toBeUndefined();
        }
    });

    it("returns false for an RS256 signature over other data", async () => {
        const crypto = createWebCrypto();
        const { key, sign } = await rsaSigner(2048);
        const signature = await sign(MSG);
        expect(
            await crypto.verifySignature(
                "RSASSA_PKCS1V15_SHA256",
                key,
                enc.encode("other"),
                signature,
            ),
        ).toBe(false);
    });

    it("rejects an RSA JWK the subtle cannot import with INVALID_ARGUMENT and no cause", async () => {
        const subtle = refusingImport(
            "RSASSA-PKCS1-v1_5",
            () => new DOMException("bad", "DataError"),
        );
        const crypto = createWebCrypto({ subtle });
        const { key } = await rsaSigner(2048);
        const error = await crypto
            .verifySignature("RSASSA_PKCS1V15_SHA256", key, MSG, new Uint8Array(256))
            .catch((e: unknown) => e);
        expect(error).toBeInstanceOf(CapabilityError);
        expect((error as CapabilityError).code).toBe("INVALID_ARGUMENT");
        expect((error as CapabilityError).cause).toBeUndefined();
    });

    it("rejects any algorithm other than RSASSA_PKCS1V15_SHA256 with UNSUPPORTED_ALGORITHM", async () => {
        const crypto = createWebCrypto();
        const { key, sign } = await rsaSigner(2048);
        const signature = await sign(MSG);
        const other = "RSASSA_PSS_SHA256" as unknown as "RSASSA_PKCS1V15_SHA256";
        expect(await codeOfRejection(crypto.verifySignature(other, key, MSG, signature))).toBe(
            "UNSUPPORTED_ALGORITHM",
        );
    });

    it("rejects a ciphertext shorter than the tag with AUTHENTICATION_FAILED and no cause", async () => {
        const crypto = createWebCrypto();
        const error = await crypto
            .aes256GcmDecrypt(new Uint8Array(32), new Uint8Array(12), MSG, new Uint8Array(15))
            .catch((e: unknown) => e);
        expect(error).toBeInstanceOf(CapabilityError);
        expect((error as CapabilityError).code).toBe("AUTHENTICATION_FAILED");
        expect((error as CapabilityError).cause).toBeUndefined();
    });

    it("rejects a modified aad with AUTHENTICATION_FAILED", async () => {
        const crypto = createWebCrypto();
        const key = new Uint8Array(32).fill(1);
        const nonce = new Uint8Array(12).fill(2);
        const sealed = await crypto.aes256GcmEncrypt(key, nonce, enc.encode("aad"), MSG);
        expect(
            await codeOfRejection(crypto.aes256GcmDecrypt(key, nonce, enc.encode("aaD"), sealed)),
        ).toBe("AUTHENTICATION_FAILED");
    });

    it("does not retain or alias the caller's buffers", async () => {
        const crypto = createWebCrypto();
        const key = new Uint8Array(32).fill(1);
        const nonce = new Uint8Array(12).fill(2);
        const plaintext = enc.encode("plaintext");
        const sealed = await crypto.aes256GcmEncrypt(key, nonce, MSG, plaintext);
        expect(sealed.buffer).not.toBe(plaintext.buffer);
        const opened = await crypto.aes256GcmDecrypt(key, nonce, MSG, sealed);
        expect(opened.buffer).not.toBe(sealed.buffer);
    });

    it("constructs without globalThis.crypto and fails closed with UNSUPPORTED", async () => {
        vi.stubGlobal("crypto", undefined);
        const crypto = createWebCrypto();
        expect(codeOfThrown(() => crypto.randomBytes(1))).toBe("UNSUPPORTED");
        expect(await codeOfRejection(crypto.sha256(MSG))).toBe("UNSUPPORTED");
        expect(
            await codeOfRejection(
                crypto.verifyEd25519(new Uint8Array(32), MSG, new Uint8Array(64)),
            ),
        ).toBe("UNSUPPORTED");
        expect(
            await codeOfRejection(
                crypto.aes256GcmEncrypt(new Uint8Array(32), new Uint8Array(12), MSG, MSG),
            ),
        ).toBe("UNSUPPORTED");
    });
});
