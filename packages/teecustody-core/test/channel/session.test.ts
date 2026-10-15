// T-26 Session (INC-2-API §7.4 "Session.request", "Nonce discipline, client side"; D2-3, D2-15, D2-16;
// SR-14 R-5) and the decrypt-side helpers of API-TL §3. verifyBundle is module-mocked (A1, TL-12); MAX_SEQ is
// lowered through a module mock so that exhaustion is reachable.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { verifyBundle } from "../../src/bundle/verify.js";
import { CapabilityError } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError } from "../../src/channel/errors.js";
import type { Session } from "../../src/channel/session.js";
import type { ChannelLimits } from "../../src/channel/types.js";
import type { CanonicalValue } from "../../src/wire/types.js";
import {
    CLIENT,
    FakeClock,
    FakeWorkload,
    TEST_LIMITS,
    asMap,
    brandedBundle,
    clientConfig,
    hex,
    instanceFixture,
    map,
    sealFrameResult,
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

async function connect(limits: ChannelLimits = TEST_LIMITS): Promise<Session> {
    const client = new ChannelClient(clientConfig(workload, clock, { limits }));
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
            const session = await connect();
            expect((await failure(session.request(op, null))).code).toBe("INVALID_ARGUMENT");
            await session.request("test.echo", echo(0));
            expect(workload.frames.map((f) => f.seq)).toEqual([0]);
        },
    );

    it("refuses a non-string op with INVALID_ARGUMENT", async () => {
        const session = await connect();
        const request = session.request.bind(session) as (
            op: unknown,
            p: unknown,
        ) => Promise<unknown>;
        expect((await failure(request(7, null))).code).toBe("INVALID_ARGUMENT");
    });

    it("refuses an encoded payload above maxPayloadBytes, and an unencodable one", async () => {
        const session = await connect({ ...TEST_LIMITS, maxPayloadBytes: 64 });
        // A 63-byte string encodes to 65 bytes (2-byte head): one above the bound.
        expect((await failure(session.request("test.echo", new Uint8Array(63)))).code).toBe(
            "INVALID_ARGUMENT",
        );
        expect(
            (await failure(session.request("test.echo", 1.5 as unknown as CanonicalValue))).code,
        ).toBe("INVALID_ARGUMENT");
        await session.request("test.echo", new Uint8Array(62)); // exactly 64 bytes
        expect(workload.frames.map((f) => f.seq)).toEqual([0]);
    });

    it("refuses more than maxInFlight pending requests without consuming a seq", async () => {
        const session = await connect({ ...TEST_LIMITS, maxInFlight: 2 });
        const results = await Promise.allSettled([
            session.request("test.echo", echo(0)),
            session.request("test.echo", echo(1)),
            session.request("test.echo", echo(2)),
        ]);
        expect(results.map((r) => r.status)).toEqual(["fulfilled", "fulfilled", "rejected"]);
        const rejected = results[2] as PromiseRejectedResult;
        expect((rejected.reason as ChannelError).code).toBe("INVALID_ARGUMENT");
        await session.request("test.echo", echo(3));
        expect(workload.frames.map((f) => f.seq)).toEqual([0, 1, 2]);
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
        const session = await connect();
        for (let n = 0; n <= 5; n += 1) {
            await session.request("test.echo", echo(n));
        }
        expect((await failure(session.request("test.echo", echo(6)))).code).toBe(
            "SEQUENCE_EXHAUSTED",
        );
        expect(session.closed).toBe(true);
        expect((await failure(session.request("test.echo", echo(7)))).code).toBe("SESSION_CLOSED");
        expect(workload.frames.map((f) => f.seq)).toEqual([0, 1, 2, 3, 4, 5]);
    });
});
