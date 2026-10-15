// Bounded X25519 key generation in createWebCrypto (T-39; ADR 0011 C8, C8.1–C8.4; B-45 §5 R1–R3;
// INC-2-API §8.1). Faults are injected on the global subtle that @hpke/core uses (C3a.3).
import { generateKeyPairSync } from "node:crypto";

import { CipherSuite } from "@hpke/core";
import { CapabilityError, type Bytes } from "@teecustody/core";
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

/** Planted in every injected platform message; it must never reach a CapabilityError (SR-11, C8.4 c). */
const SENTINEL = "T39-SENTINEL-7f3a";
/** The exception name Playwright WebKit 26.6 (rev 2359) throws from X25519 generateKey (FACTS V-2.6, B-45). */
const FAULT_NAME = "OperationError";

const enc = new TextEncoder();
const INFO = enc.encode("tee-chan-v1 info");
const AAD = enc.encode("open aad");
const PT = enc.encode("open_session payload");

/** A recipient key pair from node:crypto, so building it never touches the spied global subtle. */
function x25519(): { sk: Bytes; pk: Bytes } {
    const { publicKey, privateKey } = generateKeyPairSync("x25519");
    const priv = privateKey.export({ format: "jwk" });
    const pub = publicKey.export({ format: "jwk" });
    return {
        sk: new Uint8Array(Buffer.from(priv.d ?? "", "base64url")),
        pk: new Uint8Array(Buffer.from(pub.x ?? "", "base64url")),
    };
}

function algorithmName(algorithm: unknown): string {
    return typeof algorithm === "string" ? algorithm : (algorithm as Algorithm).name;
}

interface Harness {
    /** Ordered global subtle calls: `generateKey <alg> <probe|sender> <ok|fail>`, `exportKey`, `deriveBits <alg> <key alg>`. */
    readonly log: string[];
    /** Replaces the fault plan; `fails(n)` is asked for the n-th X25519 generateKey (n = 1 is the first). */
    setFault(fails: (call: number) => boolean): void;
    probeCalls(): number;
    senderCalls(): number;
}

/**
 * Spies generateKey, exportKey and deriveBits on globalThis.crypto.subtle. The probe is the
 * non-extractable X25519 generateKey; @hpke/core's ephemeral key is generated extractable.
 */
function harness(fails: (call: number) => boolean = () => false): Harness {
    const subtle = globalThis.crypto.subtle;
    const realGenerate = subtle.generateKey.bind(subtle) as (...a: unknown[]) => Promise<unknown>;
    const realExport = subtle.exportKey.bind(subtle) as (...a: unknown[]) => Promise<unknown>;
    const realDerive = subtle.deriveBits.bind(subtle) as (...a: unknown[]) => Promise<unknown>;
    const log: string[] = [];
    let plan = fails;
    let x25519Calls = 0;
    vi.spyOn(subtle, "generateKey").mockImplementation(((...args: unknown[]) => {
        const name = algorithmName(args[0]);
        const role = args[1] === false ? "probe" : "sender";
        if (name === "X25519") {
            x25519Calls += 1;
            if (plan(x25519Calls)) {
                log.push(`generateKey ${name} ${role} fail`);
                return Promise.reject(new DOMException(`${SENTINEL} transient`, FAULT_NAME));
            }
        }
        log.push(`generateKey ${name} ${role} ok`);
        return realGenerate(...args);
    }) as typeof subtle.generateKey);
    vi.spyOn(subtle, "exportKey").mockImplementation(((...args: unknown[]) => {
        log.push("exportKey");
        return realExport(...args);
    }) as typeof subtle.exportKey);
    vi.spyOn(subtle, "deriveBits").mockImplementation(((...args: unknown[]) => {
        const key = args[1] as CryptoKey;
        log.push(`deriveBits ${algorithmName(args[0])} ${key.algorithm.name}`);
        return realDerive(...args);
    }) as typeof subtle.deriveBits);
    const count = (role: string): number =>
        log.filter((entry) => entry.startsWith(`generateKey X25519 ${role} `)).length;
    return {
        log,
        setFault: (next) => {
            plan = next;
        },
        probeCalls: () => count("probe"),
        senderCalls: () => count("sender"),
    };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => "resolved",
        (error: unknown) => error,
    );
}

function codeOf(error: unknown): string {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

afterEach(() => {
    vi.restoreAllMocks();
    hpkeConstructed.mockClear();
});

describe("sender transient failure (criterion 1, C8.1, C5)", () => {
    it("retries the sender's ephemeral key once and the result round-trips", async () => {
        const { sk, pk } = x25519();
        const h = harness((call) => call === 2);
        const createSender = vi.spyOn(CipherSuite.prototype, "createSenderContext");
        const crypto = createWebCrypto();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(h.probeCalls()).toBe(1);
        expect(h.senderCalls()).toBe(2);
        expect(createSender).toHaveBeenCalledTimes(2);
        for (const [params] of createSender.mock.calls) {
            expect(Object.keys(params).sort()).toEqual(["info", "recipientPublicKey"]);
        }
        const ct = await sender.seal(AAD, PT);
        const receiver = await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(Array.from(await receiver.open(AAD, ct))).toEqual(Array.from(PT));
    });
});

describe("sender permanent failure (criterion 2, C8.1)", () => {
    it("fails closed with UNSUPPORTED and no cause after exactly 3 sender attempts", async () => {
        const { pk } = x25519();
        const h = harness((call) => call > 1);
        const createSender = vi.spyOn(CipherSuite.prototype, "createSenderContext");
        const crypto = createWebCrypto();
        const error = await rejection(crypto.setupHpkeSender(pk, INFO));
        expect(codeOf(error)).toBe("UNSUPPORTED");
        expect((error as CapabilityError).cause).toBeUndefined();
        expect(h.probeCalls()).toBe(1);
        expect(h.senderCalls()).toBe(3);
        expect(createSender).toHaveBeenCalledTimes(3);
        for (const result of createSender.mock.results) {
            expect(result.type).toBe("return");
            await expect(result.value).rejects.toThrow();
        }
    });
});

describe("probe transient failure (criterion 3, R1)", () => {
    it("retries a failed probe attempt and constructs the suite once", async () => {
        const { pk } = x25519();
        const h = harness((call) => call === 1);
        const crypto = createWebCrypto();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
        expect(h.probeCalls()).toBe(2);
        expect(h.senderCalls()).toBe(1);
        expect(hpkeConstructed.mock.calls.filter(([name]) => name === "CipherSuite")).toHaveLength(
            1,
        );
    });
});
