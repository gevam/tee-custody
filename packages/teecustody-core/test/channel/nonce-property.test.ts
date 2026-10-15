// T-26 criterion 8 (SR-14 R-5, High; D2-16): across random post and encrypt failures, timeouts, host retries
// and up to maxInFlight concurrent requests, no (key, nonce) pair is ever sealed twice and, per key, the seq
// sequence only grows: it is exactly 0, 1, 2, … in call order. verifyBundle is module-mocked (A1, TL-12).
import { beforeEach, describe, expect, it, vi } from "vitest";

import { verifyBundle } from "../../src/bundle/verify.js";
import { CapabilityError, type Crypto } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError } from "../../src/channel/errors.js";
import { aeadSpy } from "../support/channel-crypto.js";
import {
    CLIENT,
    FakeClock,
    FakeWorkload,
    TEST_LIMITS,
    brandedBundle,
    clientConfig,
    instanceFixture,
    map,
} from "./support.js";

vi.mock("../../src/bundle/verify.js", () => ({ verifyBundle: vi.fn() }));

// Deterministic PRNG (mulberry32) so the property run is reproducible.
function prng(seed: number): () => number {
    let a = seed >>> 0;
    return () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
    };
}

const SEALS = 1000;
const LIMITS = { ...TEST_LIMITS, responseTimeoutMs: 1500, maxInFlight: 8 };
const FAILURE_CODES = new Set(["TRANSPORT", "CRYPTO_UNAVAILABLE", "TIMEOUT"]);

let clock: FakeClock;

beforeEach(() => {
    clock = new FakeClock();
});

describe("criterion 8: R-5 nonce uniqueness property", () => {
    it.each([1, 2, 3])(
        "never reuses a (key, nonce) and never lowers seq (seed %i)",
        async (seed) => {
            const random = prng(seed);
            const fx = await instanceFixture(
                undefined,
                Array.from({ length: 8 }, (_, i) => i + 1),
            );
            const workload = new FakeWorkload(fx);
            vi.mocked(verifyBundle).mockImplementation(() =>
                Promise.resolve(brandedBundle(fx, clock.now())),
            );
            const flaky: Crypto = {
                ...workload.crypto,
                aes256GcmEncrypt: (key, nonce, aad, pt) =>
                    random() < 0.1
                        ? Promise.reject(new CapabilityError("INTERNAL"))
                        : workload.crypto.aes256GcmEncrypt(key, nonce, aad, pt),
            };
            const spy = aeadSpy(flaky);
            workload.postFailure = () =>
                random() < 0.1 ? new CapabilityError("UNAVAILABLE") : undefined;
            workload.onFrame = (frame) =>
                random() < 0.05 ? { kind: "silent" } : { kind: "ok", payload: frame.payload };
            const client = new ChannelClient(
                clientConfig(workload, clock, { crypto: spy.crypto, limits: LIMITS }),
            );

            let n = 0;
            const sessions: unknown[] = [];
            while (spy.calls.length < SEALS) {
                workload.postFailure = undefined;
                const { session } = await client.open({
                    op: "open_session",
                    clientId: CLIENT,
                    cs: new Uint8Array(32).fill(1),
                    keyId: new Uint8Array(16),
                    epoch: 0,
                });
                workload.postFailure = () =>
                    random() < 0.1 ? new CapabilityError("UNAVAILABLE") : undefined;
                for (let round = 0; round < 40 && spy.calls.length < SEALS; round += 1) {
                    const width = 1 + Math.floor(random() * LIMITS.maxInFlight);
                    const burst = await Promise.allSettled(
                        Array.from({ length: width }, () =>
                            session.request("test.echo", map({ n: n++ })),
                        ),
                    );
                    for (const result of burst) {
                        if (result.status === "rejected") {
                            const error = result.reason as ChannelError;
                            expect(FAILURE_CODES.has(error.code)).toBe(true);
                            // host retry = a new request(), which gets a new seq
                            await session
                                .request("test.echo", map({ n: n++ }))
                                .catch(() => undefined);
                        }
                    }
                }
                sessions.push(session);
            }

            expect(spy.calls.length).toBeGreaterThanOrEqual(SEALS);
            const pairs = new Set(spy.calls.map((c) => `${c.keyHex}:${c.nonceHex}`));
            expect(pairs.size).toBe(spy.calls.length);
            const byKey = new Map<string, number[]>();
            for (const call of spy.calls) {
                expect(call.nonceHex.slice(0, 8)).toBe("00000000");
                const list = byKey.get(call.keyHex) ?? [];
                list.push(Number.parseInt(call.nonceHex.slice(8), 16));
                byKey.set(call.keyHex, list);
            }
            expect(byKey.size).toBeGreaterThan(1);
            for (const seqs of byKey.values()) {
                expect(seqs).toEqual(seqs.map((_, i) => i));
            }
        },
    );
});
