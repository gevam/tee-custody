// WebCrypto Crypto adapter (INC-2-API §8.1; spec §10.2; ADR 0009 rule 5, ADR 0011).
// This file is the only @hpke/* import site in the packages (SR-14).
import { CapabilityError, type Crypto } from "@teecustody/core";

export interface WebCryptoOptions {
    readonly subtle?: SubtleCrypto; // default globalThis.crypto.subtle
    readonly getRandomValues?: (a: Uint8Array) => Uint8Array; // default globalThis.crypto.getRandomValues
}

const MAX_RANDOM_BYTES = 65536;

function notImplemented(): never {
    throw new Error("NOT_IMPLEMENTED: T-17");
}

// works in browsers and Node >= 22
export function createWebCrypto(options?: WebCryptoOptions): Crypto {
    const getRandomValues =
        options?.getRandomValues ?? ((a: Uint8Array) => globalThis.crypto.getRandomValues(a));
    return {
        randomBytes(length: number): Uint8Array {
            if (length < 1 || length > MAX_RANDOM_BYTES) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return getRandomValues(new Uint8Array(length));
        },
        sha256: notImplemented,
        verifyEd25519: notImplemented,
        verifySignature: notImplemented,
        setupHpkeSender: notImplemented,
        setupHpkeReceiver: notImplemented,
        aes256GcmEncrypt: notImplemented,
        aes256GcmDecrypt: notImplemented,
    };
}
