// Test-only channel Crypto (API-TL §3 "Test crypto"): fake HPKE, Node WebCrypto primitives, AEAD spy.
import { describe, expect, it } from "vitest";

import { CapabilityError } from "../../src/capabilities.js";
import { aeadSpy, fakeHpkeKeyPair, testChannelCrypto } from "./channel-crypto.js";

const enc = new TextEncoder();
const INFO = enc.encode("unit info");
const AAD = enc.encode("aad");

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
    const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        all.set(p, at);
        at += p.length;
    }
    return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", all));
}

function hex(b: Uint8Array): string {
    return Buffer.from(b).toString("hex");
}

describe("fakeHpkeKeyPair", () => {
    it("derives publicKey = SHA-256('fake-pk' ‖ sk) from a 32-byte random sk", async () => {
        const a = await fakeHpkeKeyPair();
        const b = await fakeHpkeKeyPair();
        expect(a.privateKey).toHaveLength(32);
        expect(hex(a.privateKey)).not.toBe(hex(b.privateKey));
        expect(a.publicKey).toEqual(await sha256(enc.encode("fake-pk"), a.privateKey));
    });
});

describe("testChannelCrypto fake HPKE", () => {
    it("opens a seal with the matching receiver and both sides export the same secrets", async () => {
        const crypto = testChannelCrypto();
        const kp = await fakeHpkeKeyPair();
        const sender = await crypto.setupHpkeSender(kp.publicKey, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
        const ct1 = await sender.seal(AAD, enc.encode("one"));
        const ct2 = await sender.seal(AAD, enc.encode("two"));
        const receiver = await crypto.setupHpkeReceiver(
            kp.privateKey,
            sender.encapsulatedKey,
            INFO,
        );
        expect(await receiver.open(AAD, ct1)).toEqual(enc.encode("one"));
        expect(await receiver.open(AAD, ct2)).toEqual(enc.encode("two"));
        const label = enc.encode("c2t");
        const sent = await sender.export(label, 32);
        expect(await receiver.export(label, 32)).toEqual(sent);
        expect(await receiver.export(label, 7)).toEqual(sent.subarray(0, 7));
        expect(await sender.export(enc.encode("t2c"), 32)).not.toEqual(sent);
    });

    it("seals with secret = SHA-256('fake-hpke' ‖ pkR ‖ enc ‖ info) and nonce 0^4 ‖ u64be(n)", async () => {
        const crypto = testChannelCrypto();
        const kp = await fakeHpkeKeyPair();
        const sender = await crypto.setupHpkeSender(kp.publicKey, INFO);
        const ct0 = await sender.seal(AAD, enc.encode("x"));
        const ct1 = await sender.seal(AAD, enc.encode("y"));
        const secret = await sha256(
            enc.encode("fake-hpke"),
            kp.publicKey,
            sender.encapsulatedKey,
            INFO,
        );
        const n0 = new Uint8Array(12);
        const n1 = new Uint8Array(12);
        n1[11] = 1;
        expect(await crypto.aes256GcmDecrypt(secret, n0, AAD, ct0)).toEqual(enc.encode("x"));
        expect(await crypto.aes256GcmDecrypt(secret, n1, AAD, ct1)).toEqual(enc.encode("y"));
        expect(await sender.export(enc.encode("L"), 32)).toEqual(
            await sha256(secret, enc.encode("L")),
        );
    });

    it("fails to open under a wrong info, a wrong key or a tampered ciphertext", async () => {
        const crypto = testChannelCrypto();
        const kp = await fakeHpkeKeyPair();
        const other = await fakeHpkeKeyPair();
        const sender = await crypto.setupHpkeSender(kp.publicKey, INFO);
        const ct = await sender.seal(AAD, enc.encode("p"));
        const wrongInfo = await crypto.setupHpkeReceiver(
            kp.privateKey,
            sender.encapsulatedKey,
            enc.encode("other info"),
        );
        await expect(wrongInfo.open(AAD, ct)).rejects.toEqual(
            new CapabilityError("AUTHENTICATION_FAILED"),
        );
        const wrongKey = await crypto.setupHpkeReceiver(
            other.privateKey,
            sender.encapsulatedKey,
            INFO,
        );
        await expect(wrongKey.open(AAD, ct)).rejects.toBeInstanceOf(CapabilityError);
        const right = await crypto.setupHpkeReceiver(kp.privateKey, sender.encapsulatedKey, INFO);
        await expect(right.open(enc.encode("other aad"), ct)).rejects.toBeInstanceOf(
            CapabilityError,
        );
    });

    it("rejects every call after destroy()", async () => {
        const crypto = testChannelCrypto();
        const kp = await fakeHpkeKeyPair();
        const sender = await crypto.setupHpkeSender(kp.publicKey, INFO);
        const receiver = await crypto.setupHpkeReceiver(
            kp.privateKey,
            sender.encapsulatedKey,
            INFO,
        );
        sender.destroy();
        receiver.destroy();
        const destroyed = new CapabilityError("INVALID_ARGUMENT");
        await expect(sender.seal(AAD, AAD)).rejects.toEqual(destroyed);
        await expect(sender.export(AAD, 32)).rejects.toEqual(destroyed);
        await expect(receiver.open(AAD, AAD)).rejects.toEqual(destroyed);
        await expect(receiver.export(AAD, 32)).rejects.toEqual(destroyed);
    });
});

describe("testChannelCrypto primitives (Node WebCrypto)", () => {
    it("returns random bytes of the requested length", () => {
        const crypto = testChannelCrypto();
        expect(crypto.randomBytes(16)).toHaveLength(16);
        expect(hex(crypto.randomBytes(16))).not.toBe(hex(crypto.randomBytes(16)));
    });

    it("hashes with SHA-256", async () => {
        const crypto = testChannelCrypto();
        expect(hex(await crypto.sha256(enc.encode("abc")))).toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    });

    it("round-trips AES-256-GCM as ct ‖ tag and rejects a wrong aad", async () => {
        const crypto = testChannelCrypto();
        const key = crypto.randomBytes(32);
        const nonce = crypto.randomBytes(12);
        const ct = await crypto.aes256GcmEncrypt(key, nonce, AAD, enc.encode("hello"));
        expect(ct).toHaveLength(5 + 16);
        expect(await crypto.aes256GcmDecrypt(key, nonce, AAD, ct)).toEqual(enc.encode("hello"));
        await expect(crypto.aes256GcmDecrypt(key, nonce, INFO, ct)).rejects.toEqual(
            new CapabilityError("AUTHENTICATION_FAILED"),
        );
    });

    it("verifies Ed25519 signatures", async () => {
        const crypto = testChannelCrypto();
        const subtle = globalThis.crypto.subtle;
        const pair = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
        const pub = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
        const msg = enc.encode("m");
        const sig = new Uint8Array(await subtle.sign("Ed25519", pair.privateKey, msg));
        expect(await crypto.verifyEd25519(pub, msg, sig)).toBe(true);
        expect(await crypto.verifyEd25519(pub, enc.encode("n"), sig)).toBe(false);
        await expect(crypto.verifyEd25519(new Uint8Array(3), msg, sig)).rejects.toEqual(
            new CapabilityError("INVALID_ARGUMENT"),
        );
    });

    it("verifies RS256 with an RSA public JWK", async () => {
        const crypto = testChannelCrypto();
        const subtle = globalThis.crypto.subtle;
        const params = {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
        };
        const pair = await subtle.generateKey(params, true, ["sign", "verify"]);
        const jwk = await subtle.exportKey("jwk", pair.publicKey);
        const msg = enc.encode("m");
        const sig = new Uint8Array(await subtle.sign(params.name, pair.privateKey, msg));
        const key = {
            format: "jwk" as const,
            jwk: { kty: "RSA" as const, n: jwk.n ?? "", e: jwk.e ?? "" },
        };
        expect(await crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, msg, sig)).toBe(true);
        expect(await crypto.verifySignature("RSASSA_PKCS1V15_SHA256", key, AAD, sig)).toBe(false);
    });
});

describe("aeadSpy", () => {
    it("records one { keyHex, nonceHex } per aes256GcmEncrypt and passes everything through", async () => {
        const spy = aeadSpy(testChannelCrypto());
        const key = new Uint8Array(32).fill(1);
        const n1 = new Uint8Array(12).fill(2);
        const n2 = new Uint8Array(12).fill(3);
        const ct = await spy.crypto.aes256GcmEncrypt(key, n1, AAD, enc.encode("a"));
        await spy.crypto.aes256GcmEncrypt(key, n2, AAD, enc.encode("b"));
        expect(await spy.crypto.aes256GcmDecrypt(key, n1, AAD, ct)).toEqual(enc.encode("a"));
        expect(spy.calls).toEqual([
            { keyHex: hex(key), nonceHex: hex(n1) },
            { keyHex: hex(key), nonceHex: hex(n2) },
        ]);
    });

    it("delegates every other Crypto method to the wrapped one without recording", async () => {
        const inner = testChannelCrypto();
        const spy = aeadSpy(inner);
        expect(spy.crypto.randomBytes(5)).toHaveLength(5);
        expect(await spy.crypto.sha256(AAD)).toEqual(await inner.sha256(AAD));
        const kp = await fakeHpkeKeyPair();
        const sender = await spy.crypto.setupHpkeSender(kp.publicKey, INFO);
        const ct = await sender.seal(AAD, enc.encode("p"));
        const receiver = await spy.crypto.setupHpkeReceiver(
            kp.privateKey,
            sender.encapsulatedKey,
            INFO,
        );
        expect(await receiver.open(AAD, ct)).toEqual(enc.encode("p"));
        await expect(spy.crypto.verifyEd25519(new Uint8Array(1), AAD, AAD)).rejects.toBeInstanceOf(
            CapabilityError,
        );
        await expect(
            spy.crypto.verifySignature(
                "RSASSA_PKCS1V15_SHA256",
                { format: "jwk", jwk: { kty: "RSA", n: "", e: "" } },
                AAD,
                AAD,
            ),
        ).rejects.toBeInstanceOf(CapabilityError);
        expect(spy.calls).toEqual([]);
    });
});
