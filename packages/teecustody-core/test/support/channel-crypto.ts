// Test-only full Crypto for Core channel unit tests (API-TL §3 "Test crypto"). Not shipped.
// Node WebCrypto for every primitive; the HPKE here is a FAKE, non-RFC construction that only lets
// Core tests seal and open without @hpke/core. It must never be used outside tests.
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type HpkeReceiverContext,
    type HpkeSenderContext,
} from "../../src/capabilities.js";
import { testCrypto } from "./webcrypto.js";

const subtle = globalThis.crypto.subtle;
const ascii = new TextEncoder();
const FAKE_PK = ascii.encode("fake-pk");
const FAKE_HPKE = ascii.encode("fake-hpke");
const KEY_BYTES = 32;

function concat(...parts: Bytes[]): Bytes {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        out.set(p, at);
        at += p.length;
    }
    return out;
}

function hex(b: Bytes): string {
    return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function randomBytes(length: number): Bytes {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

async function sha256(data: Bytes): Promise<Bytes> {
    return new Uint8Array(await subtle.digest("SHA-256", data.slice()));
}

async function aesKey(key: Bytes): Promise<CryptoKey> {
    return subtle.importKey("raw", key.slice(), "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function aes256GcmEncrypt(
    key: Bytes,
    nonce: Bytes,
    aad: Bytes,
    plaintext: Bytes,
): Promise<Bytes> {
    const params = { name: "AES-GCM", iv: nonce.slice(), additionalData: aad.slice() };
    return new Uint8Array(await subtle.encrypt(params, await aesKey(key), plaintext.slice()));
}

async function aes256GcmDecrypt(
    key: Bytes,
    nonce: Bytes,
    aad: Bytes,
    ciphertext: Bytes,
): Promise<Bytes> {
    const params = { name: "AES-GCM", iv: nonce.slice(), additionalData: aad.slice() };
    try {
        return new Uint8Array(await subtle.decrypt(params, await aesKey(key), ciphertext.slice()));
    } catch {
        throw new CapabilityError("AUTHENTICATION_FAILED");
    }
}

async function verifyEd25519(publicKey: Bytes, data: Bytes, signature: Bytes): Promise<boolean> {
    let key: CryptoKey;
    try {
        key = await subtle.importKey("raw", publicKey.slice(), "Ed25519", false, ["verify"]);
    } catch {
        throw new CapabilityError("INVALID_ARGUMENT");
    }
    return subtle.verify("Ed25519", key, signature.slice(), data.slice());
}

function nonce(n: number): Bytes {
    const out = new Uint8Array(12);
    new DataView(out.buffer).setBigUint64(4, BigInt(n));
    return out;
}

// The fake HPKE context shared by both sides: secret, a per-context message counter and destroy().
class FakeContext {
    #secret: Bytes | undefined;
    #n = 0;

    constructor(secret: Bytes) {
        this.#secret = secret;
    }

    live(): Bytes {
        if (this.#secret === undefined) throw new CapabilityError("INVALID_ARGUMENT");
        return this.#secret;
    }

    nextNonce(): Bytes {
        return nonce(this.#n++);
    }

    async export(label: Bytes, length: number): Promise<Bytes> {
        const secret = this.live();
        return (await sha256(concat(secret, label))).slice(0, length);
    }

    destroy(): void {
        this.#secret = undefined;
    }
}

async function fakeSecret(pkR: Bytes, enc: Bytes, info: Bytes): Promise<Bytes> {
    return sha256(concat(FAKE_HPKE, pkR, enc, info));
}

export interface FakeHpkeKeyPair {
    readonly privateKey: Bytes;
    readonly publicKey: Bytes;
}

// privateKey: 32 random bytes; publicKey: SHA-256("fake-pk" ‖ sk)
export async function fakeHpkeKeyPair(): Promise<FakeHpkeKeyPair> {
    const privateKey = randomBytes(KEY_BYTES);
    return { privateKey, publicKey: await sha256(concat(FAKE_PK, privateKey)) };
}

export function testChannelCrypto(): Crypto {
    return {
        ...testCrypto(),
        randomBytes,
        sha256,
        verifyEd25519,
        aes256GcmEncrypt,
        aes256GcmDecrypt,
        async setupHpkeSender(recipientPublicKey: Bytes, info: Bytes): Promise<HpkeSenderContext> {
            const encapsulatedKey = randomBytes(KEY_BYTES);
            const ctx = new FakeContext(
                await fakeSecret(recipientPublicKey, encapsulatedKey, info),
            );
            return {
                encapsulatedKey,
                seal: async (aad, plaintext) =>
                    aes256GcmEncrypt(ctx.live(), ctx.nextNonce(), aad, plaintext),
                export: (label, length) => ctx.export(label, length),
                destroy: () => {
                    ctx.destroy();
                },
            };
        },
        async setupHpkeReceiver(
            recipientPrivateKey: Bytes,
            encapsulatedKey: Bytes,
            info: Bytes,
        ): Promise<HpkeReceiverContext> {
            const pkR = await sha256(concat(FAKE_PK, recipientPrivateKey));
            const ctx = new FakeContext(await fakeSecret(pkR, encapsulatedKey, info));
            return {
                open: async (aad, ciphertext) =>
                    aes256GcmDecrypt(ctx.live(), ctx.nextNonce(), aad, ciphertext),
                export: (label, length) => ctx.export(label, length),
                destroy: () => {
                    ctx.destroy();
                },
            };
        },
    };
}

export interface AeadCall {
    readonly keyHex: string;
    readonly nonceHex: string;
}

export interface AeadSpy {
    readonly crypto: Crypto;
    readonly calls: readonly AeadCall[];
}

// Wraps a Crypto and records { keyHex, nonceHex } for every aes256GcmEncrypt call (R-5 property tests).
export function aeadSpy(inner: Crypto): AeadSpy {
    const calls: AeadCall[] = [];
    const crypto: Crypto = {
        randomBytes: (length) => inner.randomBytes(length),
        sha256: (data) => inner.sha256(data),
        verifyEd25519: (publicKey, data, signature) =>
            inner.verifyEd25519(publicKey, data, signature),
        verifySignature: (algorithm, key, data, signature) =>
            inner.verifySignature(algorithm, key, data, signature),
        setupHpkeSender: (publicKey, info) => inner.setupHpkeSender(publicKey, info),
        setupHpkeReceiver: (privateKey, enc, info) =>
            inner.setupHpkeReceiver(privateKey, enc, info),
        aes256GcmEncrypt: (key, n, aad, plaintext) => {
            calls.push({ keyHex: hex(key), nonceHex: hex(n) });
            return inner.aes256GcmEncrypt(key, n, aad, plaintext);
        },
        aes256GcmDecrypt: (key, n, aad, ciphertext) =>
            inner.aes256GcmDecrypt(key, n, aad, ciphertext),
    };
    return { crypto, calls };
}
