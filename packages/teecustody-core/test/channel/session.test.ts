// T-26 Session (INC-2-API §7.4 "Session.request", "Nonce discipline, client side"; D2-3, D2-15, D2-16;
// SR-14 R-5) and the decrypt-side helpers of API-TL §3. verifyBundle is module-mocked (A1, TL-12); MAX_SEQ is
// lowered through a module mock so that exhaustion is reachable.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { verifyBundle } from "../../src/bundle/verify.js";
import { CapabilityError, type Crypto } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError, FrameReject } from "../../src/channel/errors.js";
import {
    openT2cFrame,
    readFrameResult,
    readOpenResult,
    type Session,
} from "../../src/channel/session.js";
import type { ChannelLimits } from "../../src/channel/types.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import { aeadSpy, type AeadSpy } from "../support/channel-crypto.js";
import {
    CLIENT,
    FakeClock,
    FakeWorkload,
    TEST_LIMITS,
    asMap,
    brandedBundle,
    clientConfig,
    decodeValue,
    hex,
    holdPostUntilPolled,
    instanceFixture,
    polledAfterFrames,
    sessionNonce,
    keySpy,
    map,
    zeroed,
    sealFrameResult,
    sealOpenResult,
    type FakeSession,
    type InstanceFixture,
    type SeenFrame,
} from "./support.js";

vi.mock("../../src/bundle/verify.js", () => ({ verifyBundle: vi.fn() }));
vi.mock("../../src/channel/wire.js", async (importOriginal) => ({
    ...(await importOriginal<typeof import("../../src/channel/wire.js")>()),
    MAX_SEQ: 5,
}));

let clock: FakeClock;
let fx: InstanceFixture;
let workload: FakeWorkload;

beforeEach(async () => {
    clock = new FakeClock();
    fx = await instanceFixture();
    workload = new FakeWorkload(fx);
    vi.mocked(verifyBundle).mockReset();
    vi.mocked(verifyBundle).mockImplementation(() =>
        Promise.resolve(brandedBundle(fx, clock.now())),
    );
});

async function connect(
    limits: ChannelLimits = TEST_LIMITS,
    crypto: Crypto = workload.crypto,
): Promise<Session> {
    const client = new ChannelClient(clientConfig(workload, clock, { limits, crypto }));
    const { session } = await client.open({
        op: "open_session",
        clientId: CLIENT,
        cs: new Uint8Array(32).fill(7),
        keyId: new Uint8Array(16),
        epoch: 0,
    });
    return session;
}

function fakeSession(session: Session): FakeSession {
    const found = workload.sessions.get(hex(session.sessionId));
    if (found === undefined) {
        throw new Error("fixture: no such session");
    }
    return found;
}

async function failure(promise: Promise<unknown>): Promise<ChannelError> {
    const error: unknown = await promise.then(
        () => undefined,
        (e: unknown) => e,
    );
    if (!(error instanceof ChannelError)) {
        throw new Error(`expected a ChannelError, got ${String(error)}`);
    }
    return error;
}

function echo(n: number): CanonicalValue {
    return map({ n });
}

function nOf(frame: SeenFrame): unknown {
    return asMap(frame.payload).get("n");
}

// INC-2-API §7.4 promises distinct allocated seqs, not post order (B-26): assert the set, not the sequence.
function expectAllocatedSeqs(): void {
    const frames = workload.frames;
    expect(frames.map((f) => f.seq).sort((a, b) => a - b)).toEqual([0, 1, 2]);
    expect(frames.find((f) => nOf(f) === 3)?.seq).toBe(2);
    expect(frames.some((f) => nOf(f) === 2)).toBe(false);
    expect(
        frames
            .filter((f) => nOf(f) === 0 || nOf(f) === 1)
            .map((f) => f.seq)
            .sort((a, b) => a - b),
    ).toEqual([0, 1]);
}

// A1 (SR-14): every aes256GcmEncrypt call after connect, by nonce. A refused request must make none.
function sealedNonces(spy: AeadSpy, base: number): string[] {
    return spy.calls.slice(base).map((c) => c.nonceHex);
}

function nonces(from: number, to: number): string[] {
    return Array.from({ length: to - from + 1 }, (_, i) => hex(sessionNonce(from + i)));
}

describe("criterion 7: Session.request", () => {
    it("seals frames with seq 0, 1, 2 and returns each answer's payload", async () => {
        const session = await connect();
        for (let n = 0; n < 3; n += 1) {
            expect(asMap(await session.request("test.echo", echo(n))).get("n")).toBe(n);
        }
        expect(workload.frames.map((f) => [f.seq, f.op])).toEqual([
            [0, "test.echo"],
            [1, "test.echo"],
            [2, "test.echo"],
        ]);
        expect(workload.frames.every((f) => hex(f.sessionId) === hex(session.sessionId))).toBe(
            true,
        );
    });

    it("ignores results for another session, another op, a stale t2c seq, t2c seq 0 or another re", async () => {
        const session = await connect();
        await session.request("test.echo", echo(0)); // t2c seq 1 accepted
        workload.beforeAnswer = async (_route, _open, frame?: SeenFrame) => {
            if (frame === undefined) {
                return [];
            }
            const fs = fakeSession(session);
            const seal = (sessionId: Uint8Array, seq: number, op: string, re: number) =>
                sealFrameResult(
                    workload.crypto,
                    fs.keyT2c,
                    sessionId,
                    seq,
                    op,
                    map({ re, ok: true, payload: "forged" }),
                );
            return [
                await seal(new Uint8Array(16).fill(9), 5, frame.op, frame.seq),
                await seal(frame.sessionId, 5, "test.other", frame.seq),
                await seal(frame.sessionId, 1, frame.op, frame.seq),
                await seal(frame.sessionId, 0, frame.op, frame.seq),
                await seal(frame.sessionId, 5, frame.op, frame.seq + 1),
            ];
        };
        workload.onFrame = (frame) => {
            fakeSession(session).t2cSeq = 5; // the genuine answer uses t2c seq 6
            return { kind: "ok", payload: frame.payload };
        };
        expect(asMap(await session.request("test.echo", echo(1))).get("n")).toBe(1);
    });

    it("accepts only a t2c seq above the last accepted one, with gaps allowed", async () => {
        const session = await connect();
        fakeSession(session).t2cSeq = 3;
        await session.request("test.echo", echo(0)); // t2c seq 4
        fakeSession(session).t2cSeq = 2; // the next genuine answer reuses t2c seq 3 < 4
        workload.onFrame = () => ({ kind: "ok", payload: "late" });
        expect((await failure(session.request("test.echo", echo(1)))).code).toBe("TIMEOUT");
    });

    it.each(["close", "", "Test.Echo", "1abc", "a b", "x".repeat(65)])(
        "refuses op %j with INVALID_ARGUMENT before sealing",
        async (op) => {
            const spy = aeadSpy(workload.crypto);
            const session = await connect(TEST_LIMITS, spy.crypto);
            const base = spy.calls.length;
            expect((await failure(session.request(op, null))).code).toBe("INVALID_ARGUMENT");
            expect(spy.calls.length).toBe(base);
            await session.request("test.echo", echo(0));
            expect(workload.frames.map((f) => f.seq)).toEqual([0]);
            expect(sealedNonces(spy, base)).toEqual(nonces(0, 0));
        },
    );

    it("refuses a non-string op with INVALID_ARGUMENT", async () => {
        const spy = aeadSpy(workload.crypto);
        const session = await connect(TEST_LIMITS, spy.crypto);
        const base = spy.calls.length;
        const request = session.request.bind(session) as (
            op: unknown,
            p: unknown,
        ) => Promise<unknown>;
        expect((await failure(request(7, null))).code).toBe("INVALID_ARGUMENT");
        expect(sealedNonces(spy, base)).toEqual([]);
    });

    it("refuses an encoded payload above maxPayloadBytes, and an unencodable one", async () => {
        const spy = aeadSpy(workload.crypto);
        const session = await connect({ ...TEST_LIMITS, maxPayloadBytes: 64 }, spy.crypto);
        const base = spy.calls.length;
        // A 63-byte string encodes to 65 bytes (2-byte head): one above the bound.
        expect((await failure(session.request("test.echo", new Uint8Array(63)))).code).toBe(
            "INVALID_ARGUMENT",
        );
        expect(spy.calls.length).toBe(base);
        expect((await failure(session.request("test.echo", 1.5))).code).toBe("INVALID_ARGUMENT");
        expect(spy.calls.length).toBe(base);
        await session.request("test.echo", new Uint8Array(62)); // exactly 64 bytes
        expect(workload.frames.map((f) => f.seq)).toEqual([0]);
        expect(sealedNonces(spy, base)).toEqual(nonces(0, 0));
    });

    it("refuses more than maxInFlight pending requests without consuming a seq", async () => {
        const spy = aeadSpy(workload.crypto);
        const session = await connect({ ...TEST_LIMITS, maxInFlight: 2 }, spy.crypto);
        const base = spy.calls.length;
        const results = await Promise.allSettled([
            session.request("test.echo", echo(0)),
            session.request("test.echo", echo(1)),
            session.request("test.echo", echo(2)),
        ]);
        expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled", "rejected"]);
        const rejected = results[2] as PromiseRejectedResult;
        expect((rejected.reason as ChannelError).code).toBe("INVALID_ARGUMENT");
        await session.request("test.echo", echo(3));
        expectAllocatedSeqs();
        expect(sealedNonces(spy, base).sort()).toEqual(nonces(0, 2));
    });

    it("forced reorder: posts in completion order; the seqs are still exactly 0, 1, 2", async () => {
        const inner = workload.crypto;
        let armed = false;
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => {
            release = resolve;
        });
        let first = true;
        const spy = aeadSpy({
            ...inner,
            aes256GcmEncrypt: async (key, n, aad, pt) => {
                if (armed && first) {
                    first = false;
                    await gate;
                }
                return inner.aes256GcmEncrypt(key, n, aad, pt);
            },
        });
        const session = await connect({ ...TEST_LIMITS, maxInFlight: 2 }, spy.crypto);
        const base = spy.calls.length;
        armed = true;
        workload.afterHandle = () => {
            release();
            return Promise.resolve();
        };
        const results = await Promise.allSettled([
            session.request("test.echo", echo(0)),
            session.request("test.echo", echo(1)),
            session.request("test.echo", echo(2)),
        ]);
        expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled", "rejected"]);
        const rejected = results[2] as PromiseRejectedResult;
        expect((rejected.reason as ChannelError).code).toBe("INVALID_ARGUMENT");
        await session.request("test.echo", echo(3));
        expect(workload.frames.map((f) => f.seq).slice(0, 2)).toEqual([1, 0]);
        expectAllocatedSeqs();
        expect(sealedNonces(spy, base).sort()).toEqual(nonces(0, 2));
    });

    it("maps ok:false to REMOTE_ERROR with the detail and stays usable", async () => {
        const session = await connect();
        workload.onFrame = (frame) =>
            frame.op === "test.nothing"
                ? { kind: "error", error: "UNKNOWN_OPERATION" }
                : frame.op === "test.odd"
                  ? { kind: "error", error: "NEW_CODE" }
                  : { kind: "ok", payload: frame.payload };
        const known = await failure(session.request("test.nothing", null));
        expect([known.code, known.detail]).toEqual(["REMOTE_ERROR", "UNKNOWN_OPERATION"]);
        const unknown = await failure(session.request("test.odd", null));
        expect([unknown.code, unknown.detail]).toEqual(["REMOTE_ERROR", "UNKNOWN"]);
        expect(asMap(await session.request("test.echo", echo(2))).get("n")).toBe(2);
    });

    it("maps a failed post to TRANSPORT and an unanswered request to TIMEOUT, never re-sealing", async () => {
        const session = await connect();
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        const transport = await failure(session.request("test.echo", echo(0)));
        expect([transport.code, transport.detail]).toEqual(["TRANSPORT", "UNAVAILABLE"]);
        workload.postFailure = undefined;
        workload.onFrame = () => ({ kind: "silent" });
        expect((await failure(session.request("test.echo", echo(1)))).code).toBe("TIMEOUT");
        workload.onFrame = (frame) => ({ kind: "ok", payload: frame.payload });
        await session.request("test.echo", echo(2));
        expect(workload.posts).toHaveLength(4); // the open and three frames, none re-posted
        expect(workload.frames.map((f) => f.seq)).toEqual([1, 2]);
    });

    it("fails SEQUENCE_EXHAUSTED when the next seq would exceed MAX_SEQ, and closes locally", async () => {
        const spy = aeadSpy(workload.crypto);
        const session = await connect(TEST_LIMITS, spy.crypto);
        const base = spy.calls.length;
        for (let n = 0; n <= 5; n += 1) {
            await session.request("test.echo", echo(n));
        }
        expect(sealedNonces(spy, base)).toEqual(nonces(0, 5));
        expect((await failure(session.request("test.echo", echo(6)))).code).toBe(
            "SEQUENCE_EXHAUSTED",
        );
        expect(spy.calls.length).toBe(base + 6);
        expect(session.closed).toBe(true);
        expect((await failure(session.request("test.echo", echo(7)))).code).toBe("SESSION_CLOSED");
        expect(sealedNonces(spy, base)).toEqual(nonces(0, 5));
        expect(workload.frames.map((f) => f.seq)).toEqual([0, 1, 2, 3, 4, 5]);
    });
});

describe("criterion 12: a failing AEAD port in request()", () => {
    it.each([
        [new CapabilityError("UNSUPPORTED"), "UNSUPPORTED"],
        [new CapabilityError("UNSUPPORTED_ALGORITHM"), "UNSUPPORTED_ALGORITHM"],
    ])("maps %s to CRYPTO_UNAVAILABLE; the seq stays consumed", async (thrown, detail) => {
        let fail = false;
        const inner = workload.crypto;
        const session = await connect(TEST_LIMITS, {
            ...inner,
            aes256GcmEncrypt: (key, n, aad, pt) =>
                fail ? Promise.reject(thrown) : inner.aes256GcmEncrypt(key, n, aad, pt),
        });
        fail = true;
        const error = await failure(session.request("test.echo", echo(0)));
        expect([error.code, error.detail]).toEqual(["CRYPTO_UNAVAILABLE", detail]);
        fail = false;
        await session.request("test.echo", echo(1));
        expect(workload.frames.map((f) => f.seq)).toEqual([1]);
    });

    it("maps a ciphertext of the wrong size to CRYPTO_UNAVAILABLE INVALID_RESPONSE", async () => {
        const inner = workload.crypto;
        const session = await connect(TEST_LIMITS, {
            ...inner,
            aes256GcmEncrypt: () => Promise.resolve(new Uint8Array(3)),
        });
        const error = await failure(session.request("test.echo", echo(0)));
        expect([error.code, error.detail]).toEqual(["CRYPTO_UNAVAILABLE", "INVALID_RESPONSE"]);
        expect(workload.posts).toHaveLength(1);
    });
});

describe("review R1: the waiter is registered before the post (no lost answer)", () => {
    const SLACK = { ...TEST_LIMITS, responseTimeoutMs: 60_000 };

    it("receives an answer that another loop on the route read before the post resolved", async () => {
        const session = await connect(SLACK);
        workload.onFrame = (frame) =>
            frame.op === "test.slow" ? { kind: "silent" } : { kind: "ok", payload: frame.payload };
        const slow = session.request("test.slow", null).catch((e: unknown) => e);
        await polledAfterFrames(workload, 1);
        holdPostUntilPolled(workload, 2);
        expect(asMap(await session.request("test.echo", echo(1))).get("n")).toBe(1);
        expect(((await slow) as ChannelError).code).toBe("TIMEOUT");
    });

    it("withdraws only its own waiter when the post fails", async () => {
        const session = await connect(SLACK);
        workload.onFrame = (frame) =>
            frame.op === "test.slow" ? { kind: "silent" } : { kind: "ok", payload: frame.payload };
        const slow = session.request("test.slow", null).catch((e: unknown) => e);
        await polledAfterFrames(workload, 1);
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        expect((await failure(session.request("test.echo", echo(1)))).code).toBe("TRANSPORT");
        expect(((await slow) as ChannelError).code).toBe("TIMEOUT");
    });
});

describe("review R1: decrypt-port failures other than AUTHENTICATION_FAILED fail closed", () => {
    const KEY = new Uint8Array(32).fill(0x11);
    const SESSION = new Uint8Array(16).fill(0x22);
    const REQUEST = new Uint8Array(16).fill(0x33);

    function failingDecrypt(error: Error): Crypto {
        return { ...workload.crypto, aes256GcmDecrypt: () => Promise.reject(error) };
    }

    const CASES: [string, Error, string][] = [
        ["UNSUPPORTED", new CapabilityError("UNSUPPORTED"), "UNSUPPORTED"],
        [
            "UNSUPPORTED_ALGORITHM",
            new CapabilityError("UNSUPPORTED_ALGORITHM"),
            "UNSUPPORTED_ALGORITHM",
        ],
        ["INVALID_ARGUMENT", new CapabilityError("INVALID_ARGUMENT"), "INVALID_ARGUMENT"],
        ["a non-capability error", new TypeError("adapter bug"), "INVALID_RESPONSE"],
    ];

    it.each(CASES)("readOpenResult maps %s to CRYPTO_UNAVAILABLE", async (_n, error, detail) => {
        const body = await sealOpenResult(
            workload.crypto,
            KEY,
            SESSION,
            REQUEST,
            map({ ok: true, payload: null }),
        );
        await expect(
            readOpenResult(failingDecrypt(error), KEY, REQUEST, body, TEST_LIMITS),
        ).rejects.toEqual(new ChannelError("CRYPTO_UNAVAILABLE", detail as never));
    });

    it.each(CASES)("readFrameResult maps %s to CRYPTO_UNAVAILABLE", async (_n, error, detail) => {
        const body = await sealFrameResult(
            workload.crypto,
            KEY,
            SESSION,
            1,
            "test.echo",
            map({ re: 0, ok: true, payload: null }),
        );
        const thrown: unknown = await readFrameResult(
            failingDecrypt(error),
            KEY,
            SESSION,
            0,
            0,
            body,
            TEST_LIMITS,
        ).catch((e: unknown) => e);
        expect(thrown).toBeInstanceOf(ChannelError);
        expect([(thrown as ChannelError).code, (thrown as ChannelError).detail]).toEqual([
            "CRYPTO_UNAVAILABLE",
            detail,
        ]);
    });

    it.each(CASES)("openT2cFrame maps %s to CRYPTO_UNAVAILABLE", async (_n, error, detail) => {
        const body = await sealFrameResult(
            workload.crypto,
            KEY,
            SESSION,
            1,
            "test.echo",
            map({ re: 0, ok: true, payload: null }),
        );
        const thrown: unknown = await openT2cFrame(
            failingDecrypt(error),
            KEY,
            0,
            body,
            TEST_LIMITS,
        ).catch((e: unknown) => e);
        expect([(thrown as ChannelError).code, (thrown as ChannelError).detail]).toEqual([
            "CRYPTO_UNAVAILABLE",
            detail,
        ]);
    });

    it("a request fails CRYPTO_UNAVAILABLE instead of timing out", async () => {
        let fail = false;
        const inner = workload.crypto;
        const session = await connect(TEST_LIMITS, {
            ...inner,
            aes256GcmDecrypt: (key, n, aad, ct) =>
                fail
                    ? Promise.reject(new CapabilityError("UNSUPPORTED"))
                    : inner.aes256GcmDecrypt(key, n, aad, ct),
        });
        fail = true;
        const error = await failure(session.request("test.echo", echo(0)));
        expect([error.code, error.detail]).toEqual(["CRYPTO_UNAVAILABLE", "UNSUPPORTED"]);
    });
});

describe("review R2: no post after close, and a failed post leaves no waiter", () => {
    async function settle(): Promise<void> {
        for (let i = 0; i < 50; i += 1) {
            await new Promise((resolve) => setImmediate(resolve));
        }
    }

    it("a request still encrypting when close() completes fails SESSION_CLOSED without posting or waiting", async () => {
        const inner = workload.crypto;
        let hold: Promise<void> | undefined;
        let release: () => void = () => undefined;
        let entered: () => void = () => undefined;
        const encrypting = new Promise<void>((resolve) => {
            entered = resolve;
        });
        const session = await connect(TEST_LIMITS, {
            ...inner,
            aes256GcmEncrypt: async (key, n, aad, pt) => {
                const gate = hold;
                hold = undefined;
                if (gate !== undefined) {
                    entered();
                    await gate;
                }
                return inner.aes256GcmEncrypt(key, n, aad, pt);
            },
        });
        hold = new Promise<void>((resolve) => {
            release = resolve;
        });
        const pending = session.request("test.echo", echo(0)).catch((e: unknown) => e);
        await encrypting;
        await session.close();
        await settle();
        const posts = workload.posts.length;
        const polls = workload.polls.length;
        release();
        expect(((await pending) as ChannelError).code).toBe("SESSION_CLOSED");
        await settle();
        expect(workload.posts).toHaveLength(posts);
        expect(workload.polls).toHaveLength(polls);
        expect(workload.frames.map((f) => f.op)).toEqual(["close"]);
    });

    it("a failed post withdraws its waiter: polling stops", async () => {
        const session = await connect();
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        const started = clock.now();
        expect((await failure(session.request("test.echo", echo(0)))).code).toBe("TRANSPORT");
        const polls = workload.polls.length;
        await settle();
        expect(workload.polls.length - polls).toBeLessThanOrEqual(1);
        expect(clock.now() - started).toBeLessThan(TEST_LIMITS.responseTimeoutMs);
    });
});

describe("criterion 10: close", () => {
    async function keyed(): Promise<{
        session: Session;
        keys: () => Uint8Array[];
        encrypts: () => number;
    }> {
        const spy = keySpy(workload.crypto);
        const session = await connect(TEST_LIMITS, spy.crypto);
        await session.request("test.echo", echo(0));
        return {
            session,
            keys: () => [...spy.encryptKeys, ...spy.decryptKeys],
            encrypts: () => spy.encryptKeys.length,
        };
    }

    it("seals op close with a null payload, waits for its result and zeroes the keys", async () => {
        const { session, keys, encrypts } = await keyed();
        await session.close();
        const sealedAtClose = encrypts();
        const last = workload.frames.at(-1);
        expect([last?.op, last?.payload, last?.seq]).toEqual(["close", null, 1]);
        expect(session.closed).toBe(true);
        expect(keys().length).toBeGreaterThanOrEqual(2);
        expect(keys().every(zeroed)).toBe(true);
        expect((await failure(session.request("test.echo", echo(1)))).code).toBe("SESSION_CLOSED");
        expect(encrypts()).toBe(sealedAtClose);
        await session.close();
        expect(encrypts()).toBe(sealedAtClose);
        expect(workload.frames).toHaveLength(2);
        expect(workload.posts).toHaveLength(3);
    });

    it("zeroes the keys and is closed when the transport fails; a second close is a no-op", async () => {
        const { session, keys } = await keyed();
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        const error = await failure(session.close());
        expect([error.code, error.detail]).toEqual(["TRANSPORT", "UNAVAILABLE"]);
        expect(session.closed).toBe(true);
        expect(keys().every(zeroed)).toBe(true);
        const posts = workload.posts.length;
        await expect(session.close()).resolves.toBeUndefined();
        expect(workload.posts).toHaveLength(posts);
    });

    it("zeroes the keys when the close result never comes (TIMEOUT)", async () => {
        const { session, keys } = await keyed();
        workload.onFrame = () => ({ kind: "silent" });
        expect((await failure(session.close())).code).toBe("TIMEOUT");
        expect(session.closed).toBe(true);
        expect(keys().every(zeroed)).toBe(true);
    });

    it("surfaces a refused close as REMOTE_ERROR, still closed", async () => {
        const { session, keys } = await keyed();
        workload.onFrame = () => ({ kind: "error", error: "INTERNAL" });
        const error = await failure(session.close());
        expect([error.code, error.detail]).toEqual(["REMOTE_ERROR", "INTERNAL"]);
        expect(session.closed).toBe(true);
        expect(keys().every(zeroed)).toBe(true);
    });

    it("releases a pending request with SESSION_CLOSED", async () => {
        const session = await connect();
        workload.onFrame = (frame) =>
            frame.op === "close" ? { kind: "ok", payload: null } : { kind: "silent" };
        const pending = session.request("test.slow", null);
        await session.close();
        expect((await failure(pending)).code).toBe("SESSION_CLOSED");
    });

    it("releases a request whose post was still in flight when the session closed", async () => {
        const session = await connect();
        let release: () => void = () => undefined;
        const reached = new Promise<void>((entered) => {
            workload.postGate = () =>
                new Promise<void>((resolve) => {
                    release = resolve;
                    entered();
                });
        });
        const pending = session.request("test.echo", echo(0));
        await reached;
        workload.postGate = undefined;
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        await failure(session.close());
        workload.postFailure = undefined;
        release();
        expect((await failure(pending)).code).toBe("SESSION_CLOSED");
    });

    it("closes locally without sending when the seq space is exhausted", async () => {
        const spy = aeadSpy(workload.crypto);
        const session = await connect(TEST_LIMITS, spy.crypto);
        const base = spy.calls.length;
        for (let n = 0; n <= 5; n += 1) {
            await session.request("test.echo", echo(n));
        }
        expect((await failure(session.close())).code).toBe("SEQUENCE_EXHAUSTED");
        expect(sealedNonces(spy, base)).toEqual(nonces(0, 5));
        expect(session.closed).toBe(true);
        expect(workload.frames).toHaveLength(6);
    });
});

describe("criterion 11: decrypt-side helpers (API-TL §3)", () => {
    const KEY = new Uint8Array(32).fill(0x11);
    const SESSION = new Uint8Array(16).fill(0x22);
    const REQUEST = new Uint8Array(16).fill(0x33);

    function decryptSpy(): { crypto: Crypto; calls: () => number } {
        let calls = 0;
        const inner = workload.crypto;
        return {
            crypto: {
                ...inner,
                aes256GcmDecrypt: (key, n, aad, ct) => {
                    calls += 1;
                    return inner.aes256GcmDecrypt(key, n, aad, ct);
                },
            },
            calls: () => calls,
        };
    }

    function frame(seq: number, body: CanonicalValue, key = KEY, sessionId = SESSION) {
        return sealFrameResult(workload.crypto, key, sessionId, seq, "test.echo", body);
    }

    function openResult(
        body: CanonicalValue,
        sessionId: Uint8Array | null = SESSION,
        requestId = REQUEST,
    ) {
        return sealOpenResult(workload.crypto, KEY, sessionId, requestId, body);
    }

    const okFrame = (re: number) => map({ re, ok: true, payload: "p" });

    describe("openT2cFrame", () => {
        it("returns the aad and plaintext of a valid frame; lastSeq -1 accepts seq 0", async () => {
            const opened = await openT2cFrame(
                workload.crypto,
                KEY,
                -1,
                await frame(0, okFrame(0)),
                TEST_LIMITS,
            );
            expect(opened.aad).toEqual({ sessionId: SESSION, seq: 0, op: "test.echo" });
            expect(decodeValue(opened.plaintext)).toEqual(okFrame(0));
        });

        it("rejects bytes that do not decode as INVALID_ENVELOPE", async () => {
            await expect(
                openT2cFrame(workload.crypto, KEY, -1, new Uint8Array([0xff]), TEST_LIMITS),
            ).rejects.toEqual(new FrameReject("INVALID_ENVELOPE"));
        });

        it("rejects an open_result envelope as INVALID_ENVELOPE", async () => {
            const body = await openResult(map({ ok: true, payload: null }));
            await expect(openT2cFrame(workload.crypto, KEY, -1, body, TEST_LIMITS)).rejects.toEqual(
                new FrameReject("INVALID_ENVELOPE"),
            );
        });

        it.each([3, 4])(
            "rejects seq 3 after lastSeq %i as SEQ_REJECTED before decrypting",
            async (last) => {
                const spy = decryptSpy();
                await expect(
                    openT2cFrame(spy.crypto, KEY, last, await frame(3, okFrame(0)), TEST_LIMITS),
                ).rejects.toEqual(new FrameReject("SEQ_REJECTED"));
                expect(spy.calls()).toBe(0);
            },
        );

        it("rejects a frame under another key as AUTH_FAILED", async () => {
            const body = await frame(1, okFrame(0), new Uint8Array(32).fill(0x99));
            await expect(openT2cFrame(workload.crypto, KEY, 0, body, TEST_LIMITS)).rejects.toEqual(
                new FrameReject("AUTH_FAILED"),
            );
        });
    });

    describe("readOpenResult", () => {
        it("accepts ok with the session id and payload", async () => {
            const body = await openResult(map({ ok: true, payload: "hello" }));
            expect(await readOpenResult(workload.crypto, KEY, REQUEST, body, TEST_LIMITS)).toEqual({
                ok: true,
                sessionId: SESSION,
                payload: "hello",
            });
        });

        it.each([
            ["AUTHENTICATION_FAILED", "AUTHENTICATION_FAILED"],
            ["NOT_A_KNOWN_CODE", "UNKNOWN"],
        ])("maps the error %s to %s", async (error, mapped) => {
            const body = await openResult(map({ ok: false, error }), null);
            expect(await readOpenResult(workload.crypto, KEY, REQUEST, body, TEST_LIMITS)).toEqual({
                ok: false,
                error: mapped,
            });
        });

        it("ignores bytes that do not decode", async () => {
            expect(
                await readOpenResult(
                    workload.crypto,
                    KEY,
                    REQUEST,
                    new Uint8Array([1]),
                    TEST_LIMITS,
                ),
            ).toBeUndefined();
        });

        it("ignores a frame_result envelope", async () => {
            const body = await frame(1, okFrame(0));
            expect(
                await readOpenResult(workload.crypto, KEY, REQUEST, body, TEST_LIMITS),
            ).toBeUndefined();
        });

        it("ignores another request id without decrypting", async () => {
            const spy = decryptSpy();
            const body = await openResult(
                map({ ok: true, payload: null }),
                SESSION,
                new Uint8Array(16),
            );
            expect(
                await readOpenResult(spy.crypto, KEY, REQUEST, body, TEST_LIMITS),
            ).toBeUndefined();
            expect(spy.calls()).toBe(0);
        });

        it("ignores an AEAD failure", async () => {
            const body = await openResult(map({ ok: true, payload: null }));
            const wrong = new Uint8Array(32).fill(0x98);
            expect(
                await readOpenResult(workload.crypto, wrong, REQUEST, body, TEST_LIMITS),
            ).toBeUndefined();
        });

        it.each([
            ["an R-3 violation", map({ ok: true, payload: null }), null],
            ["a schema violation", map({ ok: 1 }), SESSION],
        ])("fails INVALID_RESPONSE on an authenticated %s", async (_name, value, sessionId) => {
            const body = await openResult(value, sessionId);
            await expect(
                readOpenResult(workload.crypto, KEY, REQUEST, body, TEST_LIMITS),
            ).rejects.toEqual(new ChannelError("INVALID_RESPONSE"));
        });
    });

    describe("readFrameResult", () => {
        const read = (
            body: Uint8Array,
            re: number,
            last: number,
            crypto: Crypto = workload.crypto,
        ) => readFrameResult(crypto, KEY, SESSION, re, last, body, TEST_LIMITS);

        it("accepts a matching ok result", async () => {
            expect(await read(await frame(2, okFrame(4)), 4, 1)).toEqual({
                seq: 2,
                op: "test.echo",
                re: 4,
                ok: true,
                payload: "p",
            });
        });

        it.each([
            ["UNKNOWN_OPERATION", "UNKNOWN_OPERATION"],
            ["SOMETHING_ELSE", "UNKNOWN"],
        ])("maps the error %s to %s", async (error, mapped) => {
            const body = await frame(2, map({ re: 4, ok: false, error }));
            expect(await read(body, 4, 1)).toEqual({
                seq: 2,
                op: "test.echo",
                re: 4,
                ok: false,
                error: mapped,
            });
        });

        it("ignores bytes that do not decode", async () => {
            expect(await read(new Uint8Array([0xa0]), 0, 0)).toBeUndefined();
        });

        it("ignores an open_result envelope", async () => {
            expect(
                await read(await openResult(map({ ok: true, payload: null })), 0, -1),
            ).toBeUndefined();
        });

        it("ignores another session without decrypting", async () => {
            const spy = decryptSpy();
            const body = await frame(2, okFrame(0), KEY, new Uint8Array(16).fill(0x44));
            expect(await read(body, 0, 0, spy.crypto)).toBeUndefined();
            expect(spy.calls()).toBe(0);
        });

        it.each([
            ["equal to lastSeq", 3, 3],
            ["below lastSeq", 2, 3],
            ["0 even with lastSeq -1 (D2-3)", 0, -1],
        ])("ignores a t2c seq %s without decrypting", async (_name, seq, last) => {
            const spy = decryptSpy();
            expect(await read(await frame(seq, okFrame(0)), 0, last, spy.crypto)).toBeUndefined();
            expect(spy.calls()).toBe(0);
        });

        it("ignores an AEAD failure", async () => {
            const body = await frame(2, okFrame(0), new Uint8Array(32).fill(0x97));
            expect(await read(body, 0, 0)).toBeUndefined();
        });

        it("ignores a result for another re", async () => {
            expect(await read(await frame(2, okFrame(5)), 4, 0)).toBeUndefined();
        });

        it("fails INVALID_RESPONSE on an authenticated schema violation", async () => {
            const body = await frame(2, map({ re: 0, ok: true }));
            await expect(read(body, 0, 0)).rejects.toEqual(new ChannelError("INVALID_RESPONSE"));
        });
    });
});
