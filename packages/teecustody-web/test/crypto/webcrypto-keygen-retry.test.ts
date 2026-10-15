// Bounded X25519 key generation in createWebCrypto (T-39; ADR 0011 C8, C8.1–C8.4; B-45 §5 R1–R3;
// INC-2-API §8.1). Faults are injected on the global subtle that @hpke/core uses (C3a.3).
import { generateKeyPairSync } from "node:crypto";

import {
    CipherSuite,
    DeserializeError,
    DhkemX25519HkdfSha256,
    EncapError,
    InvalidParamError,
    SerializeError,
    ValidationError,
} from "@hpke/core";
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

/** RFC 7748 §5 / cr.yp.to low-order u-coordinates (as in webcrypto.test.ts). */
const LOW_ORDER_ENC = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => new Uint8Array(Buffer.from(hex, "hex")));

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
        const key = args[1];
        const keyAlgorithm = key instanceof CryptoKey ? key.algorithm.name : "not-a-CryptoKey";
        log.push(`deriveBits ${algorithmName(args[0])} ${keyAlgorithm}`);
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

describe("failed probe not cached (criterion 4, R1)", () => {
    it("probes 3 times per HPKE call while X25519 fails, then recovers and caches success", async () => {
        const { sk, pk } = x25519();
        const h = harness(() => true);
        const crypto = createWebCrypto();
        for (const call of [
            () => crypto.setupHpkeSender(pk, INFO),
            () => crypto.setupHpkeReceiver(sk, pk, INFO),
            () => crypto.setupHpkeSender(pk, INFO),
        ]) {
            const before = h.probeCalls();
            expect(codeOf(await rejection(call()))).toBe("UNSUPPORTED");
            expect(h.probeCalls() - before).toBe(3);
        }
        expect(h.senderCalls()).toBe(0);
        h.setFault(() => false);
        const recovered = h.probeCalls();
        const sender = await crypto.setupHpkeSender(pk, INFO);
        expect(sender.encapsulatedKey).toHaveLength(32);
        expect(h.probeCalls() - recovered).toBe(1);
        const cached = h.probeCalls();
        await crypto.setupHpkeSender(pk, INFO);
        await crypto.setupHpkeReceiver(sk, sender.encapsulatedKey, INFO);
        expect(h.probeCalls() - cached).toBe(0);
    });
});

describe("no retry on other sender errors (criterion 5, R2.4)", () => {
    it("rejects each low-order recipient key with INVALID_ARGUMENT after 1 sender key generation", async () => {
        const h = harness();
        const crypto = createWebCrypto();
        for (const lowOrder of LOW_ORDER_ENC) {
            const before = h.senderCalls();
            const error = await rejection(crypto.setupHpkeSender(lowOrder, INFO));
            expect(codeOf(error)).toBe("INVALID_ARGUMENT");
            expect((error as CapabilityError).cause).toBeUndefined();
            expect(h.senderCalls() - before).toBe(1);
        }
    });

    it.each([
        ["EncapError", () => new EncapError(`${SENTINEL} encap`)],
        ["ValidationError", () => new ValidationError(`${SENTINEL} validation`)],
        ["InvalidParamError", () => new InvalidParamError(`${SENTINEL} param`)],
        ["SerializeError", () => new SerializeError(`${SENTINEL} serialize`)],
        ["Error", () => new Error(`${SENTINEL} plain`)],
    ] as const)("calls createSenderContext once when it rejects %s", async (_name, failure) => {
        const { pk } = x25519();
        harness();
        const createSender = vi
            .spyOn(CipherSuite.prototype, "createSenderContext")
            .mockRejectedValueOnce(failure());
        const crypto = createWebCrypto();
        const error = await rejection(crypto.setupHpkeSender(pk, INFO));
        expect(codeOf(error)).toBe("INVALID_ARGUMENT");
        expect((error as CapabilityError).cause).toBeUndefined();
        expect(createSender).toHaveBeenCalledTimes(1);
    });

    it("rejects a deserializePublicKey failure with INVALID_ARGUMENT before any sender context", async () => {
        const { pk } = x25519();
        harness();
        vi.spyOn(DhkemX25519HkdfSha256.prototype, "deserializePublicKey").mockRejectedValueOnce(
            new DeserializeError(`${SENTINEL} deserialize`),
        );
        const createSender = vi.spyOn(CipherSuite.prototype, "createSenderContext");
        const crypto = createWebCrypto();
        const error = await rejection(crypto.setupHpkeSender(pk, INFO));
        expect(codeOf(error)).toBe("INVALID_ARGUMENT");
        expect((error as CapabilityError).cause).toBeUndefined();
        expect(createSender).not.toHaveBeenCalled();
    });
});

/** The log entries that follow each failing sender generateKey, up to the next generateKey. */
function afterFailures(log: readonly string[]): string[][] {
    const runs: string[][] = [];
    log.forEach((entry, index) => {
        if (entry === "generateKey X25519 sender fail") {
            const rest = log.slice(index + 1);
            const next = rest.findIndex((e) => e.startsWith("generateKey "));
            runs.push(next === -1 ? rest : rest.slice(0, next));
        }
    });
    return runs;
}

describe("a failed attempt leaves nothing (criterion 6, C8.4 a)", () => {
    it("follows every failing sender generateKey by another generateKey or the end of the call", async () => {
        const { pk } = x25519();
        for (const fails of [
            (call: number) => call === 2,
            (call: number) => call === 2 || call === 3,
        ]) {
            const h = harness(fails);
            const crypto = createWebCrypto();
            await crypto.setupHpkeSender(pk, INFO);
            const runs = afterFailures(h.log);
            expect(runs.length).toBeGreaterThan(0);
            for (const run of runs) {
                expect(run).toEqual([]);
            }
            vi.restoreAllMocks();
        }
    });

    it("makes no exportKey or deriveBits after the probe when every sender attempt fails", async () => {
        const { pk } = x25519();
        const h = harness((call) => call > 1);
        const crypto = createWebCrypto();
        await rejection(crypto.setupHpkeSender(pk, INFO));
        const afterProbe = h.log.slice(h.log.indexOf("generateKey X25519 probe ok") + 1);
        expect(afterProbe).toEqual([
            "generateKey X25519 sender fail",
            "generateKey X25519 sender fail",
            "generateKey X25519 sender fail",
        ]);
    });
});

describe("native only (criterion 7, C8.4 b and its clarification)", () => {
    it("sends every attempt to the global subtle and makes one X25519 deriveBits per encap", async () => {
        const { pk } = x25519();
        const h = harness((call) => call === 2);
        const injected = {
            generateKey: vi.fn(),
            deriveBits: vi.fn(),
            exportKey: vi.fn(),
        } as unknown as SubtleCrypto;
        const crypto = createWebCrypto({ subtle: injected });
        await crypto.setupHpkeSender(pk, INFO);
        const generated = h.log.filter((e) => e.startsWith("generateKey "));
        expect(generated).toEqual([
            "generateKey X25519 probe ok",
            "generateKey X25519 sender fail",
            "generateKey X25519 sender ok",
        ]);
        const derived = h.log.filter((e) => e.startsWith("deriveBits "));
        expect(derived.filter((e) => e.startsWith("deriveBits X25519 "))).toEqual([
            "deriveBits X25519 X25519",
        ]);
        for (const entry of derived) {
            expect(entry).toMatch(/^deriveBits (X25519 X25519|HKDF HKDF)$/);
        }
        const failed = h.log.indexOf("generateKey X25519 sender fail");
        const retried = h.log.indexOf("generateKey X25519 sender ok");
        expect(h.log.slice(failed + 1, retried)).toEqual([]);
        for (const method of ["generateKey", "deriveBits", "exportKey"] as const) {
            expect(Reflect.get(injected, method)).not.toHaveBeenCalled();
        }
    });
});

/** SR-11: the error carries only its code; no platform or library text survives (C8.4 c). */
function expectNoPlatformText(error: unknown, code: string): void {
    expect(error).toBeInstanceOf(CapabilityError);
    const capability = error as CapabilityError;
    expect(capability.code).toBe(code);
    expect(capability.message).toBe(code);
    expect(capability.cause).toBeUndefined();
    expect(String(error)).not.toContain(SENTINEL);
    for (const name of Reflect.ownKeys(capability)) {
        expect(String(Reflect.get(capability, name))).not.toContain(SENTINEL);
    }
}

describe("SR-11 sentinel (criterion 8, C8.4 c)", () => {
    it("keeps the platform message out of the UNSUPPORTED exhaustion error", async () => {
        const { pk } = x25519();
        harness((call) => call > 1);
        const crypto = createWebCrypto();
        expectNoPlatformText(await rejection(crypto.setupHpkeSender(pk, INFO)), "UNSUPPORTED");
    });

    it("keeps the library message out of the INVALID_ARGUMENT no-retry error", async () => {
        const { pk } = x25519();
        harness();
        vi.spyOn(CipherSuite.prototype, "createSenderContext").mockRejectedValueOnce(
            new EncapError(SENTINEL),
        );
        const crypto = createWebCrypto();
        expectNoPlatformText(await rejection(crypto.setupHpkeSender(pk, INFO)), "INVALID_ARGUMENT");
    });
});
