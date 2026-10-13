// WebCrypto Crypto adapter (INC-2-API §8.1; spec §10.2; ADR 0009 rule 5, ADR 0011).
// This file is the only @hpke/* import site in the packages (SR-14).
import { CapabilityError, type Crypto } from "@teecustody/core";

export interface WebCryptoOptions {
    readonly subtle?: SubtleCrypto; // default globalThis.crypto.subtle
    readonly getRandomValues?: (a: Uint8Array) => Uint8Array; // default globalThis.crypto.getRandomValues
}

const MAX_RANDOM_BYTES = 65536;
const ED25519 = { name: "Ed25519" } as const;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const RS256: RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
const RSA_MIN_MODULUS_BITS = 2048;
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;

function gcmParams(nonce: Uint8Array, aad: Uint8Array): AesGcmParams {
    return { name: "AES-GCM", iv: nonce.slice(), additionalData: aad.slice() };
}

function notImplemented(): never {
    throw new Error("NOT_IMPLEMENTED: T-17");
}

// works in browsers and Node >= 22
export function createWebCrypto(options?: WebCryptoOptions): Crypto {
    const getRandomValues =
        options?.getRandomValues ?? ((a: Uint8Array) => globalThis.crypto.getRandomValues(a));
    const subtle = options?.subtle ?? globalThis.crypto.subtle;

    async function aesGcmKey(key: Uint8Array, nonce: Uint8Array): Promise<CryptoKey> {
        if (key.length !== AES_KEY_BYTES || nonce.length !== GCM_NONCE_BYTES) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        return subtle.importKey("raw", key.slice(), "AES-GCM", false, ["encrypt", "decrypt"]);
    }

    return {
        randomBytes(length: number): Uint8Array {
            if (length < 1 || length > MAX_RANDOM_BYTES) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return getRandomValues(new Uint8Array(length));
        },
        sha256: notImplemented,
        async verifyEd25519(publicKey, data, signature): Promise<boolean> {
            if (
                publicKey.length !== ED25519_PUBLIC_KEY_BYTES ||
                signature.length !== ED25519_SIGNATURE_BYTES
            ) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            let key: CryptoKey;
            try {
                key = await subtle.importKey("raw", publicKey.slice(), ED25519, false, ["verify"]);
            } catch {
                throw new CapabilityError("UNSUPPORTED");
            }
            return subtle.verify(ED25519, key, signature.slice(), data.slice());
        },
        async verifySignature(algorithm, key, data, signature): Promise<boolean> {
            const cryptoKey = await subtle.importKey(
                "jwk",
                { kty: "RSA", n: key.jwk.n, e: key.jwk.e },
                RS256,
                false,
                ["verify"],
            );
            const { modulusLength } = cryptoKey.algorithm as RsaHashedKeyAlgorithm;
            if (modulusLength < RSA_MIN_MODULUS_BITS) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return subtle.verify(RS256.name, cryptoKey, signature.slice(), data.slice());
        },
        setupHpkeSender: notImplemented,
        setupHpkeReceiver: notImplemented,
        async aes256GcmEncrypt(key, nonce, aad, plaintext): Promise<Uint8Array> {
            const cryptoKey = await aesGcmKey(key, nonce);
            return new Uint8Array(
                await subtle.encrypt(gcmParams(nonce, aad), cryptoKey, plaintext.slice()),
            );
        },
        async aes256GcmDecrypt(key, nonce, aad, ciphertext): Promise<Uint8Array> {
            const cryptoKey = await aesGcmKey(key, nonce);
            try {
                return new Uint8Array(
                    await subtle.decrypt(gcmParams(nonce, aad), cryptoKey, ciphertext.slice()),
                );
            } catch {
                throw new CapabilityError("AUTHENTICATION_FAILED");
            }
        },
    };
}
