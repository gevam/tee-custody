// createWebCrypto (INC-2-API §8.1; T-17 criteria 1–6, 8–10; ADR 0011). KATs: hpke-kat.test.ts.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { CapabilityError, type PublicKeyInput } from "@teecustody/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createWebCrypto } from "../../src/crypto/webcrypto.js";

/** Counts every construction of an @hpke/core class; the real implementation runs unchanged. */
const hpkeConstructed = vi.hoisted(() => vi.fn<(name: string) => void>());

vi.mock("@hpke/core", async (importOriginal) => {
    const real = await importOriginal<typeof import("@hpke/core")>();
    class CipherSuite extends real.CipherSuite {
        constructor(...args: ConstructorParameters<typeof real.CipherSuite>) {
            hpkeConstructed("CipherSuite");
            super(...args);
        }
    }
    class DhkemX25519HkdfSha256 extends real.DhkemX25519HkdfSha256 {
        constructor() {
            hpkeConstructed("DhkemX25519HkdfSha256");
            super();
        }
    }
    class HkdfSha256 extends real.HkdfSha256 {
        constructor() {
            hpkeConstructed("HkdfSha256");
            super();
        }
    }
    class Aes256Gcm extends real.Aes256Gcm {
        constructor() {
            hpkeConstructed("Aes256Gcm");
            super();
        }
    }
    return { ...real, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm };
});

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

const INFO = enc.encode("tee-chan-v1 info");
const AAD = enc.encode("open aad");
const PT = enc.encode("open_session payload");
const C2T = enc.encode("c2t");
const T2C = enc.encode("t2c");

/** RFC 7748 §5 / cr.yp.to low-order u-coordinates (the all-zero point first). */
const LOW_ORDER_ENC = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => new Uint8Array(Buffer.from(hex, "hex")));

async function x25519KeyPair(): Promise<{ sk: Uint8Array; pk: Uint8Array }> {
    const subtle = globalThis.crypto.subtle;
    const pair = (await subtle.generateKey({ name: "X25519" }, true, [
        "deriveBits",
    ])) as CryptoKeyPair;
    const jwk = await subtle.exportKey("jwk", pair.privateKey);
    return {
        sk: new Uint8Array(Buffer.from(jwk.d ?? "", "base64url")),
        pk: new Uint8Array(await subtle.exportKey("raw", pair.publicKey)),
    };
}

function hex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
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

describe("HPKE Base mode (criterion 4)", () => {
    it("round-trips seal/open and agrees on both 32-byte exports", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
        const ct = await sender.seal(AAD, PT);
        expect(ct).toHaveLength(PT.length + 16);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(hex(await receiver.open(AAD, ct))).toBe(hex(PT));
        const c2t = await sender.export(C2T, 32);
        const t2c = await sender.export(T2C, 32);
        expect(c2t).toHaveLength(32);
        expect(hex(c2t)).not.toBe(hex(t2c));
        expect(hex(await receiver.export(C2T, 32))).toBe(hex(c2t));
        expect(hex(await receiver.export(T2C, 32))).toBe(hex(t2c));
    });

    it("rejects a wrong info, a modified aad or a flipped ciphertext with AUTHENTICATION_FAILED", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const ct = await sender.seal(AAD, PT);
        const wrongInfo = await crypto.setupHpkeReceiver(
            sk,
            sender.encapsulatedKey,
            enc.encode("x"),
        );
        expect(await codeOfRejection(wrongInfo.open(AAD, ct))).toBe("AUTHENTICATION_FAILED");
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(await codeOfRejection(receiver.open(enc.encode("open aaD"), ct))).toBe(
            "AUTHENTICATION_FAILED",
        );
        const flipped = ct.slice();
        flipped[0] = (flipped[0] ?? 0) ^ 0x01;
        expect(await codeOfRejection(receiver.open(AAD, flipped))).toBe("AUTHENTICATION_FAILED");
        expect(hex(await receiver.open(AAD, ct))).toBe(hex(PT));
    });

    it("rejects a 31-byte pkR, skR or enc with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const { encapsulatedKey } = await crypto.setupHpkeSender(pk, INFO);
        expect(await codeOfRejection(crypto.setupHpkeSender(pk.slice(0, 31), INFO))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(
            await codeOfRejection(crypto.setupHpkeReceiver(sk.slice(0, 31), encapsulatedKey, INFO)),
        ).toBe("INVALID_ARGUMENT");
        expect(
            await codeOfRejection(crypto.setupHpkeReceiver(sk, encapsulatedKey.slice(0, 31), INFO)),
        ).toBe("INVALID_ARGUMENT");
    });

    it("rejects an all-zero or low-order enc with AUTHENTICATION_FAILED", async () => {
        const crypto = createWebCrypto();
        const { sk } = await x25519KeyPair();
        for (const lowOrder of LOW_ORDER_ENC) {
            expect(await codeOfRejection(crypto.setupHpkeReceiver(sk, lowOrder, INFO))).toBe(
                "AUTHENTICATION_FAILED",
            );
        }
    });

    it("refuses every call after destroy() with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const ct = await sender.seal(AAD, PT);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        sender.destroy();
        receiver.destroy();
        expect(await codeOfRejection(sender.seal(AAD, PT))).toBe("INVALID_ARGUMENT");
        expect(await codeOfRejection(sender.export(C2T, 32))).toBe("INVALID_ARGUMENT");
        expect(await codeOfRejection(receiver.open(AAD, ct))).toBe("INVALID_ARGUMENT");
        expect(await codeOfRejection(receiver.export(C2T, 32))).toBe("INVALID_ARGUMENT");
    });

    it("rejects an export length of 0 or 65, or a 65-byte label, with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        for (const context of [sender, receiver]) {
            expect(await codeOfRejection(context.export(C2T, 0))).toBe("INVALID_ARGUMENT");
            expect(await codeOfRejection(context.export(C2T, 65))).toBe("INVALID_ARGUMENT");
            expect(await codeOfRejection(context.export(new Uint8Array(65), 32))).toBe(
                "INVALID_ARGUMENT",
            );
        }
    });
});

/** Makes `globalThis.crypto.subtle.generateKey` reject for X25519 (as a browser without it does). */
function hideGlobalX25519(): { restore: () => void; probes: () => number } {
    const subtle = globalThis.crypto.subtle;
    const real = subtle.generateKey.bind(subtle) as (...a: unknown[]) => Promise<unknown>;
    let probes = 0;
    const spy = vi.spyOn(subtle, "generateKey").mockImplementation(((...args: unknown[]) => {
        const algorithm = args[0] as AlgorithmIdentifier;
        if ((typeof algorithm === "string" ? algorithm : algorithm.name) === "X25519") {
            probes += 1;
            return Promise.reject(new DOMException("no X25519", "NotSupportedError"));
        }
        return real(...args);
    }) as typeof subtle.generateKey);
    return {
        restore: () => {
            spy.mockRestore();
        },
        probes: () => probes,
    };
}

describe("native X25519 only (criterion 5, C3, C3a.3)", () => {
    it("rejects both HPKE setups with UNSUPPORTED and no output when global X25519 is missing", async () => {
        const { sk, pk } = await x25519KeyPair();
        const hidden = hideGlobalX25519();
        try {
            const crypto = createWebCrypto();
            const sender = crypto.setupHpkeSender(pk, INFO);
            expect(await codeOfRejection(sender)).toBe("UNSUPPORTED");
            expect(await codeOfRejection(crypto.setupHpkeReceiver(sk, pk, INFO))).toBe(
                "UNSUPPORTED",
            );
            expect(await sender.catch(() => "no output")).toBe("no output");
            expect(hidden.probes()).toBe(1);
        } finally {
            hidden.restore();
        }
    });

    it("probes the global subtle even when options.subtle supports X25519", async () => {
        const { pk } = await x25519KeyPair();
        const injected = refusingImport("none", () => new Error("unused"));
        const hidden = hideGlobalX25519();
        try {
            const crypto = createWebCrypto({ subtle: injected });
            expect(await codeOfRejection(crypto.setupHpkeSender(pk, INFO))).toBe("UNSUPPORTED");
        } finally {
            hidden.restore();
        }
    });

    it("has no @hpke/dhkem-x25519 (JS curve) in the lock file or the module graph", () => {
        const lock = readFileSync(new URL("../../../../pnpm-lock.yaml", import.meta.url), "utf8");
        expect(lock).not.toContain("@hpke/dhkem-x25519");
        expect(lock).toContain("'@hpke/core@1.9.0'");
        const require = createRequire(import.meta.url);
        expect(() => require.resolve("@hpke/dhkem-x25519")).toThrow();
    });
});

/** The parameter list of a function's source text, whitespace-normalised. */
function parameterList(fn: unknown): string {
    const source = Function.prototype.toString.call(fn);
    const open = source.indexOf("(");
    const close = source.indexOf(")", open);
    return source
        .slice(open, close + 1)
        .replace(/\s+/g, " ")
        .replace("( ", "(")
        .replace(/,? \)$/, ")");
}

describe("no HPKE seams (criterion 8, C5)", () => {
    it("exposes exactly (recipientPublicKey, info) and (recipientPrivateKey, encapsulatedKey, info)", () => {
        const crypto = createWebCrypto();
        const sender = Reflect.get(crypto, "setupHpkeSender") as (...a: unknown[]) => unknown;
        const receiver = Reflect.get(crypto, "setupHpkeReceiver") as (...a: unknown[]) => unknown;
        expect(parameterList(sender)).toBe("(recipientPublicKey, info)");
        expect(parameterList(receiver)).toBe("(recipientPrivateKey, encapsulatedKey, info)");
        expect(sender).toHaveLength(2);
        expect(receiver).toHaveLength(3);
    });
});

describe("no globalThis.crypto (criterion 9, C7a.3)", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("rejects every HPKE call with UNSUPPORTED and never touches @hpke/core", async () => {
        const { sk, pk } = await x25519KeyPair();
        hpkeConstructed.mockClear();
        vi.stubGlobal("crypto", undefined);
        const crypto = createWebCrypto();
        expect(await codeOfRejection(crypto.setupHpkeSender(pk, INFO))).toBe("UNSUPPORTED");
        expect(await codeOfRejection(crypto.setupHpkeReceiver(sk, pk, INFO))).toBe("UNSUPPORTED");
        expect(hpkeConstructed).not.toHaveBeenCalled();
    });

    it("re-checks the global on every call, even after a successful probe", async () => {
        const { sk, pk } = await x25519KeyPair();
        const crypto = createWebCrypto();
        await crypto.setupHpkeSender(pk, INFO);
        vi.stubGlobal("crypto", undefined);
        expect(await codeOfRejection(crypto.setupHpkeSender(pk, INFO))).toBe("UNSUPPORTED");
        expect(await codeOfRejection(crypto.setupHpkeReceiver(sk, pk, INFO))).toBe("UNSUPPORTED");
    });

    it("constructs the @hpke/core suite only after a successful probe", async () => {
        hpkeConstructed.mockClear();
        const crypto = createWebCrypto();
        const { pk } = await x25519KeyPair();
        expect(hpkeConstructed).not.toHaveBeenCalled();
        await crypto.setupHpkeSender(pk, INFO);
        expect(hpkeConstructed.mock.calls.map(([name]) => name).sort()).toEqual([
            "Aes256Gcm",
            "CipherSuite",
            "DhkemX25519HkdfSha256",
            "HkdfSha256",
        ]);
    });
});

/** Records the algorithm name of every `globalThis.crypto.subtle.deriveBits` call. */
function spyDeriveBits(): { names: () => string[]; restore: () => void } {
    const spy = vi.spyOn(globalThis.crypto.subtle, "deriveBits");
    return {
        names: () =>
            spy.mock.calls.map(([algorithm]) =>
                typeof algorithm === "string" ? algorithm : algorithm.name,
            ),
        restore: () => {
            spy.mockRestore();
        },
    };
}

describe("native X25519 path (criterion 10, C3a.3)", () => {
    it("runs every encap and decap of the round trip through global deriveBits X25519", async () => {
        const { sk, pk } = await x25519KeyPair();
        const crypto = createWebCrypto();
        const derive = spyDeriveBits();
        try {
            const sender = await crypto.setupHpkeSender(pk, INFO);
            const afterEncap = derive.names().filter((n) => n === "X25519").length;
            expect(afterEncap).toBeGreaterThanOrEqual(1);
            const ct = await sender.seal(AAD, PT);
            const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
            const afterDecap = derive.names().filter((n) => n === "X25519").length;
            expect(afterDecap).toBeGreaterThan(afterEncap);
            expect(hex(await receiver.open(AAD, ct))).toBe(hex(PT));
        } finally {
            derive.restore();
        }
    });
});

describe("HPKE edge cases", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("rejects a non-integer export length with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        const { pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(await codeOfRejection(sender.export(C2T, 1.5))).toBe("INVALID_ARGUMENT");
        expect(await sender.export(new Uint8Array(64), 64)).toHaveLength(64);
        expect(await sender.export(new Uint8Array(0), 1)).toHaveLength(1);
    });

    it("rejects a low-order recipient public key with INVALID_ARGUMENT and no cause", async () => {
        const crypto = createWebCrypto();
        for (const lowOrder of LOW_ORDER_ENC) {
            const error = await crypto.setupHpkeSender(lowOrder, INFO).catch((e: unknown) => e);
            expect(error).toBeInstanceOf(CapabilityError);
            expect((error as CapabilityError).code).toBe("INVALID_ARGUMENT");
            expect((error as CapabilityError).cause).toBeUndefined();
        }
    });

    it("treats destroy() as idempotent", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = await x25519KeyPair();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        for (const context of [sender, receiver]) {
            context.destroy();
            expect(() => {
                context.destroy();
            }).not.toThrow();
        }
    });

    it("fails closed when globalThis.crypto has no subtle (insecure context)", async () => {
        const { sk, pk } = await x25519KeyPair();
        vi.stubGlobal("crypto", { getRandomValues: (a: Uint8Array) => a });
        const crypto = createWebCrypto();
        expect(await codeOfRejection(crypto.setupHpkeSender(pk, INFO))).toBe("UNSUPPORTED");
        expect(await codeOfRejection(crypto.setupHpkeReceiver(sk, pk, INFO))).toBe("UNSUPPORTED");
        expect(await codeOfRejection(crypto.sha256(MSG))).toBe("UNSUPPORTED");
    });
});
