// SR-14 / NFR-4 / ADR 0011: the WebCrypto adapter's HPKE (RFC 9180 Base, X25519 / HKDF-SHA256 /
// AES-256-GCM), AEAD and Ed25519 behaviour (INC-2-API 8.1). Cross-checked with node:crypto.
//
// Owning task: T-17 (createWebCrypto). Expected failure on trunk: Error("NOT_IMPLEMENTED: T-17").
import { createCipheriv, createDecipheriv, generateKeyPairSync, sign } from "node:crypto";

import { CapabilityError, type Bytes } from "@teecustody/core";
import { createWebCrypto } from "@teecustody/web";
import { afterEach, describe, expect, it } from "vitest";

import { expectThrown } from "./e2e-support.js";

const enc = new TextEncoder();
const INFO = enc.encode("tee-chan-v1-info");
const AAD = enc.encode("aad-bytes");
const PT = enc.encode("plaintext");

function x25519(): { sk: Bytes; pk: Bytes } {
    const { publicKey, privateKey } = generateKeyPairSync("x25519");
    const priv = privateKey.export({ format: "jwk" });
    const pub = publicKey.export({ format: "jwk" });
    return {
        sk: new Uint8Array(Buffer.from(priv.d ?? "", "base64url")),
        pk: new Uint8Array(Buffer.from(pub.x ?? "", "base64url")),
    };
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function code(error: unknown): string {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

/** SubtleCrypto proxy that records deriveBits algorithm names and can hide X25519 / Ed25519. */
function proxySubtle(options: { hide?: readonly string[] } = {}): {
    subtle: SubtleCrypto;
    derived: string[];
} {
    const real = globalThis.crypto.subtle;
    const derived: string[] = [];
    const hidden = new Set(options.hide ?? []);
    const nameOf = (a: unknown): string =>
        typeof a === "string" ? a : ((a as { name?: string }).name ?? "");
    const guard = (algorithm: unknown): void => {
        if (hidden.has(nameOf(algorithm))) {
            throw new DOMException("not supported", "NotSupportedError");
        }
    };
    const subtle = new Proxy(real, {
        get(target, prop) {
            const value = Reflect.get(target, prop, target) as unknown;
            if (typeof value !== "function") {
                return value;
            }
            return (...args: unknown[]) => {
                if (prop === "deriveBits") {
                    derived.push(nameOf(args[0]));
                }
                if (prop === "importKey") {
                    guard(args[2]);
                } else if (prop === "generateKey" || prop === "deriveBits" || prop === "verify") {
                    guard(args[0]);
                }
                return (value as (...a: unknown[]) => unknown).apply(target, args);
            };
        },
    });
    return { subtle, derived };
}

/** D-051(b), ADR 0011 C3a.3: HPKE uses only globalThis.crypto.subtle, never an injected one. */
function installGlobalSubtle(subtle: SubtleCrypto): void {
    Object.defineProperty(globalThis.crypto, "subtle", { value: subtle, configurable: true });
}

afterEach(() => {
    Reflect.deleteProperty(globalThis.crypto, "subtle");
});

describe("SR-14 HPKE Base mode through the adapter", () => {
    it("round-trips seal/open, agrees on both exports, and binds info and aad", async () => {
        // Given a recipient key pair and the adapter
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        // When the sender seals and the receiver opens with the same info and aad
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
        const ct = await sender.seal(AAD, PT);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        // Then the plaintext matches and ciphertext is plaintext plus a 16-byte tag
        expect(ct).toHaveLength(PT.length + 16);
        expect(Array.from(await receiver.open(AAD, ct))).toEqual(Array.from(PT));
        // And both sides export identical, distinct, 32-byte session keys
        const c2tS = await sender.export(enc.encode("c2t"), 32);
        const t2cS = await sender.export(enc.encode("t2c"), 32);
        expect(Array.from(await receiver.export(enc.encode("c2t"), 32))).toEqual(Array.from(c2tS));
        expect(Array.from(await receiver.export(enc.encode("t2c"), 32))).toEqual(Array.from(t2cS));
        expect(c2tS).toHaveLength(32);
        expect(Buffer.from(c2tS).equals(Buffer.from(t2cS))).toBe(false);
    });

    it("fails to open under a different aad, a different info, or a flipped ciphertext bit", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const ct = await sender.seal(AAD, PT);
        const wrongAad = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(code(await failure(wrongAad.open(enc.encode("other"), ct)))).toBe(
            "AUTHENTICATION_FAILED",
        );
        const wrongInfo = await crypto.setupHpkeReceiver(
            sk,
            sender.encapsulatedKey,
            enc.encode("x"),
        );
        expect(code(await failure(wrongInfo.open(AAD, ct)))).toBe("AUTHENTICATION_FAILED");
        const flipped = ct.slice();
        flipped[0] = (flipped[0] ?? 0) ^ 1;
        const fresh = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(code(await failure(fresh.open(AAD, flipped)))).toBe("AUTHENTICATION_FAILED");
    });

    it("rejects an all-zero (low-order) encapsulated key", async () => {
        const crypto = createWebCrypto();
        const { sk } = x25519();
        const error = await failure(
            crypto
                .setupHpkeReceiver(sk, new Uint8Array(32), INFO)
                .then((r) => r.open(AAD, new Uint8Array(32))),
        );
        expect(code(error)).toBe("AUTHENTICATION_FAILED");
    });

    it("uses a fresh ephemeral key per sender", async () => {
        const crypto = createWebCrypto();
        const { pk } = x25519();
        const a = await crypto.setupHpkeSender(pk, INFO);
        const b = await crypto.setupHpkeSender(pk, INFO);
        expect(Buffer.from(a.encapsulatedKey).equals(Buffer.from(b.encapsulatedKey))).toBe(false);
    });

    it("validates key and label lengths and refuses use after destroy", async () => {
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        expect(code(await failure(crypto.setupHpkeSender(pk.slice(0, 31), INFO)))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(code(await failure(crypto.setupHpkeReceiver(sk.slice(0, 31), pk, INFO)))).toBe(
            "INVALID_ARGUMENT",
        );
        const sender = await crypto.setupHpkeSender(pk, INFO);
        for (const [label, length] of [
            [new Uint8Array(65), 32],
            [enc.encode("c2t"), 0],
            [enc.encode("c2t"), 65],
        ] as const) {
            expect(code(await failure(sender.export(label, length)))).toBe("INVALID_ARGUMENT");
        }
        sender.destroy();
        expect(code(await failure(sender.seal(AAD, PT)))).toBe("INVALID_ARGUMENT");
    });

    it("runs X25519 on the native WebCrypto path for every encap and decap", async () => {
        const { subtle, derived } = proxySubtle();
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const ct = await sender.seal(AAD, PT);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        await receiver.open(AAD, ct);
        expect(derived.filter((n) => n === "X25519").length).toBeGreaterThanOrEqual(2);
        // every algorithm used is native WebCrypto: X25519 for the DH, HKDF for the key schedule
        expect(derived.every((n) => n === "X25519" || n === "HKDF")).toBe(true);
    });

    it("fails closed with UNSUPPORTED when native X25519 is missing (no JS curve fallback)", async () => {
        const { subtle } = proxySubtle({ hide: ["X25519"] });
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        expect(code(await failure(crypto.setupHpkeSender(pk, INFO)))).toBe("UNSUPPORTED");
        expect(code(await failure(crypto.setupHpkeReceiver(sk, pk, INFO)))).toBe("UNSUPPORTED");
    });
});

describe("AES-256-GCM through the adapter", () => {
    const key = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(12).fill(5);

    it("equals an independent node:crypto computation (ciphertext || 16-byte tag)", async () => {
        const crypto = createWebCrypto();
        const out = await crypto.aes256GcmEncrypt(key, nonce, AAD, PT);
        const cipher = createCipheriv("aes-256-gcm", key, nonce);
        cipher.setAAD(AAD);
        const expected = Buffer.concat([cipher.update(PT), cipher.final(), cipher.getAuthTag()]);
        expect(Buffer.from(out).equals(expected)).toBe(true);
        expect(Array.from(await crypto.aes256GcmDecrypt(key, nonce, AAD, out))).toEqual(
            Array.from(PT),
        );
        const decipher = createDecipheriv("aes-256-gcm", key, nonce);
        decipher.setAAD(AAD);
        decipher.setAuthTag(out.slice(out.length - 16));
        expect(
            Buffer.concat([decipher.update(out.slice(0, -16)), decipher.final()]).equals(
                Buffer.from(PT),
            ),
        ).toBe(true);
    });

    it("rejects a tampered ciphertext, aad or nonce with AUTHENTICATION_FAILED", async () => {
        const crypto = createWebCrypto();
        const out = await crypto.aes256GcmEncrypt(key, nonce, AAD, PT);
        const bad = out.slice();
        bad[0] = (bad[0] ?? 0) ^ 1;
        expect(code(await failure(crypto.aes256GcmDecrypt(key, nonce, AAD, bad)))).toBe(
            "AUTHENTICATION_FAILED",
        );
        expect(code(await failure(crypto.aes256GcmDecrypt(key, nonce, enc.encode("x"), out)))).toBe(
            "AUTHENTICATION_FAILED",
        );
        expect(
            code(await failure(crypto.aes256GcmDecrypt(key, new Uint8Array(12).fill(6), AAD, out))),
        ).toBe("AUTHENTICATION_FAILED");
    });

    it("rejects wrong key and nonce lengths with INVALID_ARGUMENT", async () => {
        const crypto = createWebCrypto();
        expect(code(await failure(crypto.aes256GcmEncrypt(key.slice(0, 31), nonce, AAD, PT)))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(code(await failure(crypto.aes256GcmEncrypt(key, nonce.slice(0, 11), AAD, PT)))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(code(await failure(crypto.aes256GcmDecrypt(key, nonce.slice(0, 11), AAD, PT)))).toBe(
            "INVALID_ARGUMENT",
        );
    });
});

describe("Ed25519 and randomness through the adapter", () => {
    it("verifies a node:crypto Ed25519 signature and rejects an altered message", async () => {
        const crypto = createWebCrypto();
        const { publicKey, privateKey } = generateKeyPairSync("ed25519");
        const jwk = publicKey.export({ format: "jwk" });
        const pk = new Uint8Array(Buffer.from(jwk.x ?? "", "base64url"));
        const sig = new Uint8Array(sign(null, Buffer.from(PT), privateKey));
        expect(await crypto.verifyEd25519(pk, PT, sig)).toBe(true);
        expect(await crypto.verifyEd25519(pk, enc.encode("other"), sig)).toBe(false);
        expect(code(await failure(crypto.verifyEd25519(pk.slice(0, 31), PT, sig)))).toBe(
            "INVALID_ARGUMENT",
        );
        expect(code(await failure(crypto.verifyEd25519(pk, PT, sig.slice(0, 63))))).toBe(
            "INVALID_ARGUMENT",
        );
    });

    it("reports UNSUPPORTED when Ed25519 is missing", async () => {
        const { subtle } = proxySubtle({ hide: ["Ed25519"] });
        const crypto = createWebCrypto({ subtle });
        const error = await failure(
            crypto.verifyEd25519(new Uint8Array(32), PT, new Uint8Array(64)),
        );
        expect(code(error)).toBe("UNSUPPORTED");
    });

    it("returns the requested number of random bytes within 1..65536", () => {
        const crypto = createWebCrypto();
        const a = crypto.randomBytes(16);
        const b = crypto.randomBytes(16);
        expect(a).toHaveLength(16);
        expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
        for (const n of [0, -1, 65537, 1.5]) {
            expectThrown(() => crypto.randomBytes(n), new CapabilityError("INVALID_ARGUMENT"));
        }
    });
});

/** Counts X25519 generateKey calls in order (call 1 = the probe) and injects faults by call number. */
function faultSubtle(fault: (call: number) => "reject" | "hide" | undefined): {
    subtle: SubtleCrypto;
    calls: () => number;
} {
    const real = globalThis.crypto.subtle;
    let calls = 0;
    const subtle = new Proxy(real, {
        get(target, prop) {
            const value = Reflect.get(target, prop, target) as unknown;
            if (typeof value !== "function") {
                return value;
            }
            return (...args: unknown[]) => {
                if (prop === "generateKey") {
                    const a = args[0];
                    const name = typeof a === "string" ? a : ((a as { name?: string }).name ?? "");
                    if (name === "X25519") {
                        calls += 1;
                        const f = fault(calls);
                        if (f === "reject") {
                            throw new DOMException("T14-SENTINEL-c8 transient", "OperationError");
                        }
                        if (f === "hide") {
                            throw new DOMException("not supported", "NotSupportedError");
                        }
                    }
                }
                return (value as (...a: unknown[]) => unknown).apply(target, args);
            };
        },
    });
    return { subtle, calls: () => calls };
}

function hex(s: string): Uint8Array {
    return new Uint8Array(Buffer.from(s, "hex"));
}

const LOW_ORDER: readonly (readonly [string, Uint8Array])[] = [
    ["zero", new Uint8Array(32)],
    ["one", hex("01" + "00".repeat(31))],
    ["order-8 a", hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")],
    ["order-8 b", hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")],
    ["p-1", hex("ecff" + "ff".repeat(29) + "7f")],
    ["p", hex("edff" + "ff".repeat(29) + "7f")],
    ["p+1", hex("eeff" + "ff".repeat(29) + "7f")],
];

describe("SR-14 bounded X25519 key generation (ADR 0011 C8)", () => {
    it("Q1: a transient failure of the sender's ephemeral key (call 2) is retried and round-trips", async () => {
        const { subtle, calls } = faultSubtle((n) => (n === 2 ? "reject" : undefined));
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { sk, pk } = x25519();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        const ct = await sender.seal(AAD, PT);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(Array.from(await receiver.open(AAD, ct))).toEqual(Array.from(PT));
        expect(calls()).toBeGreaterThanOrEqual(3);
    });

    it("Q2: every call after the probe failing gives UNSUPPORTED without a cause", async () => {
        const { subtle } = faultSubtle((n) => (n > 1 ? "reject" : undefined));
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { pk } = x25519();
        const error = await failure(crypto.setupHpkeSender(pk, INFO));
        expect(code(error)).toBe("UNSUPPORTED");
        expect((error as CapabilityError).cause).toBeUndefined();
    });

    it("Q3: a failed probe (call 1 only) is retried and the sender resolves", async () => {
        const { subtle } = faultSubtle((n) => (n === 1 ? "reject" : undefined));
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { pk } = x25519();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
    });

    it("Q4: a failed probe is not cached; the same adapter recovers when X25519 returns", async () => {
        let hidden = true;
        const { subtle } = faultSubtle(() => (hidden ? "hide" : undefined));
        installGlobalSubtle(subtle);
        const crypto = createWebCrypto();
        const { pk } = x25519();
        expect(code(await failure(crypto.setupHpkeSender(pk, INFO)))).toBe("UNSUPPORTED");
        hidden = false;
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
    });

    it.each(LOW_ORDER)(
        "Q5: low-order recipient key (%s) gives INVALID_ARGUMENT after exactly one keygen past the probe",
        async (_name, key) => {
            const { subtle, calls } = faultSubtle(() => undefined);
            installGlobalSubtle(subtle);
            const crypto = createWebCrypto();
            expect(code(await failure(crypto.setupHpkeSender(key, INFO)))).toBe("INVALID_ARGUMENT");
            expect(calls()).toBe(2);
        },
    );
});
