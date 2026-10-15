// WebCrypto Crypto adapter (INC-2-API §8.1; spec §10.2; ADR 0009 rule 5, ADR 0011).
// No other file in the packages uses @hpke/* (SR-14); the names taken from @hpke/core are exactly the
// ADR 0011 C3a.2 list.
import {
    Aes256Gcm,
    CipherSuite,
    DhkemX25519HkdfSha256,
    HkdfSha256,
    NotSupportedError,
} from "@hpke/core";
import {
    CapabilityError,
    type Bytes,
    type Crypto,
    type HpkeReceiverContext,
    type HpkeSenderContext,
} from "@teecustody/core";

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
const X25519_KEY_BYTES = 32;
const MAX_EXPORT_LABEL_BYTES = 64;
const MAX_EXPORT_BYTES = 64;
/** ADR 0011 C8 (B-45): total attempts per X25519 key generation; WebKit's generateKey fails transiently. */
const X25519_KEYGEN_ATTEMPTS = 3;

function gcmParams(nonce: Uint8Array, aad: Uint8Array): AesGcmParams {
    return { name: "AES-GCM", iv: nonce.slice(), additionalData: aad.slice() };
}

/** The platform object `globalThis.crypto`, which may be absent (fail closed, never polyfilled). */
interface PlatformCrypto {
    readonly subtle?: SubtleCrypto; // undefined outside a secure context (browsers)
    getRandomValues(array: Uint8Array): Uint8Array;
}

function platformCrypto(): PlatformCrypto | undefined {
    return (globalThis as { readonly crypto?: PlatformCrypto }).crypto;
}

function isNotSupported(error: unknown): boolean {
    return error instanceof DOMException && error.name === "NotSupportedError";
}

/** Runs `attempt` up to X25519_KEYGEN_ATTEMPTS times; rethrows at once if `retryable(error)` is false. */
async function boundedKeygen<T>(
    attempt: () => Promise<T>,
    retryable: (error: unknown) => boolean,
): Promise<T> {
    for (let remaining = X25519_KEYGEN_ATTEMPTS; ; remaining -= 1) {
        try {
            return await attempt();
        } catch (error: unknown) {
            if (remaining <= 1 || !retryable(error)) {
                throw error;
            }
        }
    }
}

type SenderContext = Awaited<ReturnType<CipherSuite["createSenderContext"]>>;
type RecipientContext = Awaited<ReturnType<CipherSuite["createRecipientContext"]>>;

function requireKeyLength(key: Bytes): void {
    if (key.length !== X25519_KEY_BYTES) {
        throw new CapabilityError("INVALID_ARGUMENT");
    }
}

/** A live @hpke/core context until destroy(); afterwards every call rejects INVALID_ARGUMENT. */
class ContextHandle<T extends SenderContext | RecipientContext> {
    #context: T | undefined;

    constructor(context: T) {
        this.#context = context;
    }

    use(): T {
        if (this.#context === undefined) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        return this.#context;
    }

    async export(label: Bytes, length: number): Promise<Bytes> {
        const context = this.use();
        if (
            label.length > MAX_EXPORT_LABEL_BYTES ||
            !Number.isInteger(length) ||
            length < 1 ||
            length > MAX_EXPORT_BYTES
        ) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        return new Uint8Array(await context.export(label.slice(), length));
    }

    destroy(): void {
        this.#context = undefined;
    }
}

// works in browsers and Node >= 22
export function createWebCrypto(options?: WebCryptoOptions): Crypto {
    const platform = platformCrypto();
    const getRandomValues = options?.getRandomValues ?? platform?.getRandomValues.bind(platform);
    const resolvedSubtle = options?.subtle ?? platform?.subtle;

    function subtle(): SubtleCrypto {
        if (resolvedSubtle === undefined) {
            throw new CapabilityError("UNSUPPORTED");
        }
        return resolvedSubtle;
    }

    let suite: Promise<CipherSuite | undefined> | undefined;

    /** ADR 0011 C3a.3: one X25519 probe per adapter, on the global subtle that @hpke/* uses. */
    async function probeSuite(globalSubtle: SubtleCrypto): Promise<CipherSuite | undefined> {
        try {
            await globalSubtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
        } catch {
            return undefined;
        }
        return new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
        });
    }

    /** ADR 0011 C7a.3: no @hpke/* call unless `globalThis.crypto.subtle` exists right now. */
    async function hpkeSuite(): Promise<CipherSuite> {
        const globalSubtle = platformCrypto()?.subtle;
        if (globalSubtle === undefined) {
            throw new CapabilityError("UNSUPPORTED");
        }
        suite ??= probeSuite(globalSubtle);
        const ready = await suite;
        if (ready === undefined) {
            throw new CapabilityError("UNSUPPORTED");
        }
        return ready;
    }

    async function aesGcmKey(key: Uint8Array, nonce: Uint8Array): Promise<CryptoKey> {
        if (key.length !== AES_KEY_BYTES || nonce.length !== GCM_NONCE_BYTES) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        return subtle().importKey("raw", key.slice(), "AES-GCM", false, ["encrypt", "decrypt"]);
    }

    return {
        randomBytes(length: number): Uint8Array {
            if (!Number.isInteger(length) || length < 1 || length > MAX_RANDOM_BYTES) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            if (getRandomValues === undefined) {
                throw new CapabilityError("UNSUPPORTED");
            }
            return getRandomValues(new Uint8Array(length));
        },
        async sha256(data): Promise<Uint8Array> {
            return new Uint8Array(await subtle().digest("SHA-256", data.slice()));
        },
        async verifyEd25519(publicKey, data, signature): Promise<boolean> {
            if (
                publicKey.length !== ED25519_PUBLIC_KEY_BYTES ||
                signature.length !== ED25519_SIGNATURE_BYTES
            ) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            const platformSubtle = subtle();
            let key: CryptoKey;
            try {
                key = await platformSubtle.importKey("raw", publicKey.slice(), ED25519, false, [
                    "verify",
                ]);
            } catch (error: unknown) {
                throw new CapabilityError(
                    isNotSupported(error) ? "UNSUPPORTED" : "INVALID_ARGUMENT",
                );
            }
            return platformSubtle.verify(ED25519, key, signature.slice(), data.slice());
        },
        async verifySignature(algorithm, key, data, signature): Promise<boolean> {
            if ((algorithm as string) !== "RSASSA_PKCS1V15_SHA256") {
                throw new CapabilityError("UNSUPPORTED_ALGORITHM");
            }
            const platformSubtle = subtle();
            let cryptoKey: CryptoKey;
            try {
                cryptoKey = await platformSubtle.importKey(
                    "jwk",
                    { kty: "RSA", n: key.jwk.n, e: key.jwk.e },
                    RS256,
                    false,
                    ["verify"],
                );
            } catch {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            const { modulusLength } = cryptoKey.algorithm as RsaHashedKeyAlgorithm;
            if (modulusLength < RSA_MIN_MODULUS_BITS) {
                throw new CapabilityError("INVALID_ARGUMENT");
            }
            return platformSubtle.verify(RS256.name, cryptoKey, signature.slice(), data.slice());
        },
        async setupHpkeSender(recipientPublicKey, info): Promise<HpkeSenderContext> {
            requireKeyLength(recipientPublicKey);
            const hpke = await hpkeSuite();
            let context: SenderContext;
            try {
                const publicKey = await hpke.kem.deserializePublicKey(recipientPublicKey.slice());
                context = await boundedKeygen(
                    () =>
                        hpke.createSenderContext({
                            recipientPublicKey: publicKey,
                            info: info.slice(),
                        }),
                    () => true,
                );
            } catch (error: unknown) {
                throw new CapabilityError(
                    error instanceof NotSupportedError ? "UNSUPPORTED" : "INVALID_ARGUMENT",
                );
            }
            const handle = new ContextHandle(context);
            return {
                encapsulatedKey: new Uint8Array(context.enc),
                async seal(aad, plaintext): Promise<Bytes> {
                    const live = handle.use();
                    return new Uint8Array(await live.seal(plaintext.slice(), aad.slice()));
                },
                export: (label, length) => handle.export(label, length),
                destroy: () => {
                    handle.destroy();
                },
            };
        },
        async setupHpkeReceiver(
            recipientPrivateKey,
            encapsulatedKey,
            info,
        ): Promise<HpkeReceiverContext> {
            requireKeyLength(recipientPrivateKey);
            requireKeyLength(encapsulatedKey);
            const hpke = await hpkeSuite();
            let context: RecipientContext;
            try {
                const privateKey = await hpke.kem.deserializePrivateKey(
                    recipientPrivateKey.slice(),
                );
                context = await hpke.createRecipientContext({
                    recipientKey: privateKey,
                    enc: encapsulatedKey.slice(),
                    info: info.slice(),
                });
            } catch {
                throw new CapabilityError("AUTHENTICATION_FAILED");
            }
            const handle = new ContextHandle(context);
            return {
                async open(aad, ciphertext): Promise<Bytes> {
                    const live = handle.use();
                    try {
                        return new Uint8Array(await live.open(ciphertext.slice(), aad.slice()));
                    } catch {
                        throw new CapabilityError("AUTHENTICATION_FAILED");
                    }
                },
                export: (label, length) => handle.export(label, length),
                destroy: () => {
                    handle.destroy();
                },
            };
        },
        async aes256GcmEncrypt(key, nonce, aad, plaintext): Promise<Uint8Array> {
            const cryptoKey = await aesGcmKey(key, nonce);
            return new Uint8Array(
                await subtle().encrypt(gcmParams(nonce, aad), cryptoKey, plaintext.slice()),
            );
        },
        async aes256GcmDecrypt(key, nonce, aad, ciphertext): Promise<Uint8Array> {
            const cryptoKey = await aesGcmKey(key, nonce);
            try {
                return new Uint8Array(
                    await subtle().decrypt(gcmParams(nonce, aad), cryptoKey, ciphertext.slice()),
                );
            } catch {
                throw new CapabilityError("AUTHENTICATION_FAILED");
            }
        },
    };
}
