// T-26 ChannelClient open flow (INC-2-API §7.4 steps (1)–(7); FR-4; SR-1 B-13, SR-4, SR-14 R-4).
// verifyBundle is module-mocked (A1, TL-12); the fake workload answers through the fake Transport.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { BundleError, createVerifiedBundle, type VerifiedBundle } from "../../src/bundle/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import { CapabilityError, type Crypto, type HpkeSenderContext } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError } from "../../src/channel/errors.js";
import {
    DEFAULT_CHANNEL_LIMITS,
    type ChannelClientConfig,
    type ChannelLimits,
    type OpenPayload,
} from "../../src/channel/types.js";
import {
    CLIENT,
    FakeClock,
    ROUTE_PATTERN,
    TEST_LIMITS,
    asMap,
    decode,
    hex,
    holdPostUntilPolled,
    polledAfterFrames,
    map,
    FakeWorkload,
    brandedBundle,
    clientConfig,
    instanceFixture,
    sealFrameResult,
    sealOpenResult,
    senderSpy,
    zeroed,
    type InstanceFixture,
    type SeenOpen,
} from "./support.js";

vi.mock("../../src/bundle/verify.js", () => ({ verifyBundle: vi.fn() }));

let clock: FakeClock;
let fx: InstanceFixture;
let workload: FakeWorkload;

function serveBundles(...fixtures: InstanceFixture[]): void {
    vi.mocked(verifyBundle).mockImplementation((published) => {
        const found = fixtures.find((f) => f.instanceId === published.instanceId);
        return found === undefined
            ? Promise.reject(new Error("fixture: unknown instance"))
            : Promise.resolve(brandedBundle(found, clock.now()));
    });
}

beforeEach(async () => {
    vi.mocked(verifyBundle).mockReset();
    clock = new FakeClock();
    fx = await instanceFixture();
    workload = new FakeWorkload(fx);
    serveBundles(fx);
});

function openSession(cs = new Uint8Array(32).fill(7)) {
    return {
        op: "open_session" as const,
        clientId: CLIENT,
        cs,
        keyId: new Uint8Array(16).fill(3),
        epoch: 4,
    };
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

describe("criterion 1: open_session", () => {
    it("seals the CDDL payload under an AAD naming the client, zeroes cs and pt, and returns a session", async () => {
        const cs = new Uint8Array(32).fill(7);
        const client = new ChannelClient(clientConfig(workload, clock));
        const { session } = await client.open(openSession(cs));

        expect(workload.opens).toHaveLength(1);
        const seen = workload.opens[0];
        expect(seen?.aad.get("client_id")).toBe(CLIENT);
        expect(seen?.aad.get("instance_id")).toBe(fx.instanceId);
        expect([...(seen?.plaintext.keys() ?? [])].sort()).toEqual(["cs", "epoch", "key_id", "op"]);
        expect(seen?.plaintext.get("op")).toBe("open_session");
        expect(seen?.plaintext.get("cs")).toEqual(new Uint8Array(32).fill(7));
        expect(seen?.plaintext.get("key_id")).toEqual(new Uint8Array(16).fill(3));
        expect(seen?.plaintext.get("epoch")).toBe(4);
        expect(cs.every((b) => b === 0)).toBe(true);

        expect(session.clientId).toBe(CLIENT);
        expect(session.instanceId).toBe(fx.instanceId);
        expect(session.sessionId).toHaveLength(16);
        expect([...workload.sessions.keys()]).toEqual([
            Array.from(session.sessionId, (b) => b.toString(16).padStart(2, "0")).join(""),
        ]);
    });

    it("zeroes the plaintext buffer it sealed", async () => {
        const sealed: Uint8Array[] = [];
        const crypto = workload.crypto;
        const client = new ChannelClient(
            clientConfig(workload, clock, {
                crypto: {
                    ...crypto,
                    setupHpkeSender: async (pub, info) => {
                        const ctx = await crypto.setupHpkeSender(pub, info);
                        return {
                            encapsulatedKey: ctx.encapsulatedKey,
                            seal: (aad, pt) => {
                                sealed.push(pt);
                                return ctx.seal(aad, pt);
                            },
                            export: (label, length) => ctx.export(label, length),
                            destroy: () => {
                                ctx.destroy();
                            },
                        };
                    },
                },
            }),
        );
        await client.open(openSession());
        expect(sealed).toHaveLength(1);
        expect(sealed[0]?.length).toBeGreaterThan(32);
        expect(sealed[0]?.every((b) => b === 0)).toBe(true);
    });
});

describe("criterion 2: enroll reply route (R-4)", () => {
    const ENROLLED = "e5".repeat(16);

    it("uses a fresh randomBytes(16) route per enrol and takes the client id from the result", async () => {
        const drawn: string[] = [];
        const crypto = workload.crypto;
        workload.onOpen = () => ({ kind: "ok", payload: map({ client_id: ENROLLED }) });
        const client = new ChannelClient(
            clientConfig(workload, clock, {
                crypto: {
                    ...crypto,
                    randomBytes: (length) => {
                        const out = crypto.randomBytes(length);
                        if (length === 16) {
                            drawn.push(hex(out));
                        }
                        return out;
                    },
                },
            }),
        );
        const first = await client.open({ op: "enroll" });
        const second = await client.open({ op: "enroll" });

        const routes = workload.opens.map((o) => o.aad.get("client_id") as string);
        expect(routes).toHaveLength(2);
        expect(routes[0]).not.toBe(routes[1]);
        for (const route of routes) {
            expect(route).toMatch(ROUTE_PATTERN);
            expect(drawn).toContain(route);
        }
        expect(workload.opens.map((o) => o.plaintext.get("op"))).toEqual(["enroll", "enroll"]);
        expect(first.session.clientId).toBe(ENROLLED);
        expect(second.session.clientId).toBe(ENROLLED);
        expect(asMap(first.payload).get("client_id")).toBe(ENROLLED);
    });

    it.each([
        ["no client_id", map({ other: 1 })],
        ["an upper-case client_id", map({ client_id: "E5".repeat(16) })],
        ["a short client_id", map({ client_id: "e5".repeat(15) })],
        ["a byte-string client_id", map({ client_id: new Uint8Array(16) })],
        ["a non-map payload", "e5".repeat(16)],
        ["a null payload", null],
    ])("refuses an enrol result with %s (INVALID_RESPONSE)", async (_name, payload) => {
        workload.onOpen = () => ({ kind: "ok", payload });
        const client = new ChannelClient(clientConfig(workload, clock));
        expect((await failure(client.open({ op: "enroll" }))).code).toBe("INVALID_RESPONSE");
    });
});

describe("criterion 3: only branded, fresh bundles are used (B-13)", () => {
    function literalOf(bundle: VerifiedBundle): VerifiedBundle {
        return {
            instanceId: bundle.instanceId,
            identityPublicKey: bundle.identityPublicKey,
            attestation: bundle.attestation,
            prekeys: bundle.prekeys,
            verifiedAtMs: bundle.verifiedAtMs,
        } as unknown as VerifiedBundle;
    }

    it("refuses a structurally identical unbranded bundle and sends nothing", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const forged = literalOf(brandedBundle(fx, clock.now()));
        expect((await failure(client.open(openSession(), forged))).code).toBe("UNVERIFIED_BUNDLE");
        expect(workload.posts).toHaveLength(0);
        expect(verifyBundle).not.toHaveBeenCalled();
    });

    it("refuses a branded bundle whose attestation is an unbranded copy", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const real = brandedBundle(fx, clock.now());
        const bundle = createVerifiedBundle({
            instanceId: real.instanceId,
            identityPublicKey: real.identityPublicKey,
            attestation: { ...real.attestation },
            prekeys: real.prekeys,
            verifiedAtMs: real.verifiedAtMs,
        });
        expect((await failure(client.open({ op: "enroll" }, bundle))).code).toBe(
            "UNVERIFIED_BUNDLE",
        );
        expect(workload.posts).toHaveLength(0);
    });

    it("refuses an unbranded bundle returned by the verifier as well", async () => {
        vi.mocked(verifyBundle).mockImplementation(() =>
            Promise.resolve(literalOf(brandedBundle(fx, clock.now()))),
        );
        const client = new ChannelClient(clientConfig(workload, clock));
        expect((await failure(client.open(openSession()))).code).toBe("UNVERIFIED_BUNDLE");
        expect(workload.posts).toHaveLength(0);
    });

    it("uses a fresh given bundle without fetching", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        await client.open(
            openSession(),
            brandedBundle(fx, clock.now() - TEST_LIMITS.bundleMaxAgeMs),
        );
        expect(verifyBundle).not.toHaveBeenCalled();
        expect(workload.opens).toHaveLength(1);
    });

    it("re-fetches when the given bundle is older than bundleMaxAgeMs", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const stale = brandedBundle(fx, clock.now() - TEST_LIMITS.bundleMaxAgeMs - 1);
        await client.open(openSession(), stale);
        expect(verifyBundle).toHaveBeenCalledTimes(1);
        expect(workload.opens).toHaveLength(1);
    });

    it("re-fetches when the given bundle's attestation has expired", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const expired = brandedBundle(fx, clock.now(), clock.now());
        await client.open(openSession(), expired);
        expect(verifyBundle).toHaveBeenCalledTimes(1);
    });
});

describe("criterion 4: no verified bundle, no usable pre-key", () => {
    it("fails NO_VERIFIED_BUNDLE when the verifier rejects every published bundle, and sends nothing", async () => {
        const other = await instanceFixture("d4".repeat(16));
        workload = new FakeWorkload(fx, other);
        vi.mocked(verifyBundle).mockRejectedValue(new BundleError("ATTESTATION_FAILED"));
        const client = new ChannelClient(clientConfig(workload, clock));
        expect((await failure(client.fetchVerifiedBundles())).code).toBe("NO_VERIFIED_BUNDLE");
        expect((await failure(client.open(openSession()))).code).toBe("NO_VERIFIED_BUNDLE");
        expect(verifyBundle).toHaveBeenCalledTimes(4);
        expect(workload.posts).toHaveLength(0);
    });

    it("discards the bundles that fail and keeps the ones that verify", async () => {
        const other = await instanceFixture("d4".repeat(16));
        workload = new FakeWorkload(other, fx);
        serveBundles(fx);
        const client = new ChannelClient(clientConfig(workload, clock));
        const bundles = await client.fetchVerifiedBundles();
        expect(bundles.map((b) => b.instanceId)).toEqual([fx.instanceId]);
    });

    it("fails NO_USABLE_PREKEY once every pre-key of the instance has been used", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        for (let i = 0; i < fx.prekeys.length; i += 1) {
            await client.open(openSession());
        }
        const ids = workload.opens.map((o) => o.aad.get("prekey_id"));
        expect(new Set(ids).size).toBe(fx.prekeys.length);
        expect((await failure(client.open(openSession()))).code).toBe("NO_USABLE_PREKEY");
        expect(workload.posts).toHaveLength(fx.prekeys.length);
    });

    it("keeps the used set per instance and per client", async () => {
        const first = new ChannelClient(clientConfig(workload, clock));
        for (let i = 0; i < fx.prekeys.length; i += 1) {
            await first.open(openSession());
        }
        const second = new ChannelClient(clientConfig(workload, clock));
        await second.open(openSession());
        expect(workload.opens).toHaveLength(fx.prekeys.length + 1);
    });
});

describe("fetchVerifiedBundles bounds and transport failures", () => {
    it("passes the profile, the event sink and its capabilities and limits to verifyBundle", async () => {
        const config = clientConfig(workload, clock);
        const client = new ChannelClient(config);
        await client.fetchVerifiedBundles();
        const [published, profile, events, deps] = vi.mocked(verifyBundle).mock.calls[0] ?? [];
        expect(published?.instanceId).toBe(fx.instanceId);
        expect(profile).toBe(config.trustProfile);
        expect(events).toBe(config.securityEvents);
        expect(deps?.crypto).toBe(config.crypto);
        expect(deps?.fetcher).toBe(config.fetcher);
        expect(deps?.verifierLimits).toEqual(TEST_LIMITS.verifier);
        expect(deps?.bundleLimits).toEqual(TEST_LIMITS.bundle);
        clock.t += 1234;
        expect(deps?.now()).toBe(clock.now());
    });

    it("verifies at most maxBundles published bundles and ignores the rest", async () => {
        const fixtures: InstanceFixture[] = [];
        for (let i = 0; i < 4; i += 1) {
            fixtures.push(await instanceFixture(`a${String(i)}`.repeat(16), [1]));
        }
        workload = new FakeWorkload(...fixtures);
        serveBundles(...fixtures);
        const client = new ChannelClient(
            clientConfig(workload, clock, { limits: { ...TEST_LIMITS, maxBundles: 3 } }),
        );
        const bundles = await client.fetchVerifiedBundles();
        expect(bundles.map((b) => b.instanceId)).toEqual(
            fixtures.slice(0, 3).map((f) => f.instanceId),
        );
        expect(verifyBundle).toHaveBeenCalledTimes(3);
    });

    it.each([
        [new CapabilityError("UNAVAILABLE"), "UNAVAILABLE"],
        [new Error("not a capability error"), undefined],
    ])("maps a listBundles failure to TRANSPORT (%s)", async (error, detail) => {
        workload.listFailure = error;
        const client = new ChannelClient(clientConfig(workload, clock));
        const thrown = await failure(client.fetchVerifiedBundles());
        expect(thrown.code).toBe("TRANSPORT");
        expect(thrown.detail).toBe(detail);
        expect(verifyBundle).not.toHaveBeenCalled();
    });
});

describe("criterion 5: a failed post", () => {
    it("fails TRANSPORT with the capability code, keeps the pre-key used and never re-seals", async () => {
        const spy = senderSpy(workload.crypto);
        workload.postFailure = () => new CapabilityError("UNAVAILABLE");
        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        const error = await failure(client.open(openSession()));
        expect(error.code).toBe("TRANSPORT");
        expect(error.detail).toBe("UNAVAILABLE");
        expect(spy.setups).toHaveLength(1);
        expect(spy.sealed).toHaveLength(1);
        expect(workload.posts).toHaveLength(1);
        expect(spy.exported).toHaveLength(2);
        expect(spy.exported.every(zeroed)).toBe(true);
        expect(spy.destroyed).toEqual([0]);

        workload.postFailure = undefined;
        await client.open(openSession());
        const prekeyOf = (body: Uint8Array): unknown =>
            decode(decode(body).get("aad") as Uint8Array).get("prekey_id");
        const [failedPost, retryPost] = workload.posts;
        expect(prekeyOf(retryPost?.body ?? new Uint8Array())).not.toBe(
            prekeyOf(failedPost?.body ?? new Uint8Array()),
        );
    });
});

describe("criterion 6: unauthenticated responses are ignored (SR-4, FR-4 §5.6)", () => {
    function flip(body: Uint8Array): Uint8Array {
        const out = body.slice();
        out[out.length - 1] = (out[out.length - 1] ?? 0) ^ 1;
        return out;
    }

    async function noise(seen: SeenOpen | undefined, count: number): Promise<Uint8Array[]> {
        if (seen === undefined) {
            return [];
        }
        const requestId = seen.aad.get("request_id") as Uint8Array;
        const otherId = requestId.map((b) => b ^ 0xff);
        const sessionId = new Uint8Array(16).fill(1);
        const genuine = await sealOpenResult(
            workload.crypto,
            seen.keyT2c,
            sessionId,
            requestId,
            map({ ok: true, payload: null }),
        );
        const kinds = [
            new Uint8Array([0xff, 0x00, 0x01]),
            await sealOpenResult(
                workload.crypto,
                seen.keyT2c,
                sessionId,
                otherId,
                map({ ok: true, payload: null }),
            ),
            flip(genuine),
            await sealOpenResult(
                workload.crypto,
                new Uint8Array(32).fill(9),
                sessionId,
                requestId,
                map({ ok: true, payload: null }),
            ),
            await sealFrameResult(
                workload.crypto,
                seen.keyT2c,
                sessionId,
                1,
                "test.echo",
                map({ re: 0, ok: true, payload: null }),
            ),
        ];
        return Array.from({ length: count }, (_, i) => kinds[i % kinds.length] as Uint8Array);
    }

    it("ignores garbage, another request id, a bit-flipped ct, a wrong key and a frame result", async () => {
        workload.beforeAnswer = (_route, seen) => noise(seen, 5);
        const client = new ChannelClient(clientConfig(workload, clock));
        const { session } = await client.open(openSession());
        expect(session.clientId).toBe(CLIENT);
    });

    it("survives a flood of 1 000 such bodies before the real answer (SR-4 victim flood)", async () => {
        workload.beforeAnswer = (_route, seen) => noise(seen, 1000);
        const client = new ChannelClient(
            clientConfig(workload, clock, { limits: DEFAULT_CHANNEL_LIMITS }),
        );
        const { session } = await client.open(openSession());
        expect(session.instanceId).toBe(fx.instanceId);
        expect(workload.polls.length).toBeGreaterThan(1000 / workload.pageSize);
        expect(clock.sleeps.every((ms) => ms === DEFAULT_CHANNEL_LIMITS.pollIntervalMs)).toBe(true);
    });

    it.each([
        ["ok with a nil session id", null, map({ ok: true, payload: null })],
        [
            "an error with a session id",
            new Uint8Array(16).fill(2),
            map({ ok: false, error: "INTERNAL" }),
        ],
        ["a plaintext outside the schema", new Uint8Array(16).fill(2), map({ ok: "yes" })],
    ])("fails INVALID_RESPONSE on an authenticated %s (R-3)", async (_name, sessionId, body) => {
        const spy = senderSpy(workload.crypto);
        workload.onOpen = () => ({ kind: "silent" });
        workload.beforeAnswer = async (_route, seen) =>
            seen === undefined
                ? []
                : [
                      await sealOpenResult(
                          workload.crypto,
                          seen.keyT2c,
                          sessionId,
                          seen.aad.get("request_id") as Uint8Array,
                          body,
                      ),
                  ];
        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        expect((await failure(client.open(openSession()))).code).toBe("INVALID_RESPONSE");
        expect(spy.exported.every(zeroed)).toBe(true);
    });

    it.each([
        ["AUTHENTICATION_FAILED", "AUTHENTICATION_FAILED"],
        ["UNKNOWN_OPERATION", "UNKNOWN_OPERATION"],
        ["SOMETHING_NEW", "UNKNOWN"],
    ])(
        "fails REMOTE_ERROR on ok:false %s, with the mapped detail and zeroed keys",
        async (code, detail) => {
            const spy = senderSpy(workload.crypto);
            workload.onOpen = () => ({ kind: "error", error: code });
            const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
            const error = await failure(client.open(openSession()));
            expect([error.code, error.detail]).toEqual(["REMOTE_ERROR", detail]);
            expect(spy.exported.every(zeroed)).toBe(true);
        },
    );

    it("fails TIMEOUT after responseTimeoutMs without an answer, with zeroed keys", async () => {
        const spy = senderSpy(workload.crypto);
        workload.onOpen = () => ({ kind: "silent" });
        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        const started = clock.now();
        expect((await failure(client.open(openSession()))).code).toBe("TIMEOUT");
        expect(clock.now() - started).toBeGreaterThanOrEqual(TEST_LIMITS.responseTimeoutMs);
        expect(clock.now() - started).toBeLessThan(
            TEST_LIMITS.responseTimeoutMs + 2 * TEST_LIMITS.pollIntervalMs,
        );
        expect(spy.exported.every(zeroed)).toBe(true);
    });

    it("retries polling after transport errors until the answer arrives", async () => {
        let failures = 3;
        workload.pollFailure = () =>
            failures-- > 0 ? new CapabilityError("UNAVAILABLE") : undefined;
        const client = new ChannelClient(clientConfig(workload, clock));
        await client.open(openSession());
        expect(workload.polls).toHaveLength(4);
    });

    it("fails TIMEOUT when every poll fails", async () => {
        workload.pollFailure = () => new CapabilityError("UNAVAILABLE");
        const client = new ChannelClient(clientConfig(workload, clock));
        expect((await failure(client.open(openSession()))).code).toBe("TIMEOUT");
    });
});

describe("response routing: one poll loop per route, cursor kept per client route", () => {
    it("resumes a route from the cursor its last exchange reached", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const first = await client.open(openSession());
        await first.session.request("test.echo", map({ n: 1 }));
        await first.session.close();
        const before = workload.polls.length;
        await client.open(openSession());
        const resumed = workload.polls[before];
        expect(resumed?.route).toBe(CLIENT);
        expect(resumed?.after).toBe("3");
    });

    it("does not re-read a long route history on the next open", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const { session } = await client.open(openSession());
        for (let n = 0; n < 200; n += 1) {
            await session.request("test.echo", map({ n }));
        }
        await session.close();
        const before = workload.polls.length;
        await client.open(openSession());
        expect(workload.opens).toHaveLength(2);
        const after = workload.polls.slice(before).map((p) => p.after);
        expect(after.length).toBeGreaterThan(0);
        expect(after.every((cursor) => cursor === "202")).toBe(true);
    });

    it("never polls an enrol reply route again after its open", async () => {
        workload.onOpen = () => ({ kind: "ok", payload: map({ client_id: CLIENT }) });
        const client = new ChannelClient(clientConfig(workload, clock));
        const { session } = await client.open({ op: "enroll" });
        const route = workload.opens[0]?.aad.get("client_id");
        const routePolls = () => workload.polls.filter((p) => p.route === route).length;
        const duringOpen = routePolls();
        expect(duringOpen).toBeGreaterThan(0);
        await session.request("test.echo", map({ n: 1 }));
        await client.open(openSession());
        expect(routePolls()).toBe(duringOpen);
        expect(workload.polls.filter((p) => p.route === CLIENT).length).toBeGreaterThan(0);
    });

    it("closing one session releases only its own pending requests", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const a = await client.open(openSession());
        const b = await client.open(openSession());
        workload.onFrame = (frame) =>
            frame.op === "test.slow" ? { kind: "silent" } : { kind: "ok", payload: null };
        const pendingA = a.session.request("test.slow", null).catch((e: unknown) => e);
        const pendingB = b.session.request("test.slow", null).catch((e: unknown) => e);
        await a.session.close();
        expect(((await pendingA) as ChannelError).code).toBe("SESSION_CLOSED");
        expect(((await pendingB) as ChannelError).code).toBe("TIMEOUT");
    });

    it("an open receives an answer that a session's loop on the route read before the post resolved", async () => {
        const client = new ChannelClient(
            clientConfig(workload, clock, {
                limits: { ...TEST_LIMITS, responseTimeoutMs: 60_000 },
            }),
        );
        const first = await client.open(openSession());
        workload.onFrame = () => ({ kind: "silent" });
        const slow = first.session.request("test.slow", null).catch((e: unknown) => e);
        await polledAfterFrames(workload, 1);
        holdPostUntilPolled(workload, 2);
        const second = await client.open(openSession());
        expect(second.session.clientId).toBe(CLIENT);
        expect(((await slow) as ChannelError).code).toBe("TIMEOUT");
    });

    it("serves two sessions of the same client from one route", async () => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const a = await client.open(openSession());
        const b = await client.open(openSession());
        const [ra, rb] = await Promise.all([
            a.session.request("test.echo", map({ n: 1 })),
            b.session.request("test.echo", map({ n: 2 })),
        ]);
        expect([asMap(ra).get("n"), asMap(rb).get("n")]).toEqual([1, 2]);
        await a.session.close();
        expect(asMap(await b.session.request("test.echo", map({ n: 3 }))).get("n")).toBe(3);
    });
});

describe("criterion 12: Crypto-port failures fail closed as CRYPTO_UNAVAILABLE", () => {
    type Patch = (inner: Crypto) => Partial<Crypto>;

    function senderWith(
        inner: Crypto,
        change: (ctx: HpkeSenderContext) => Partial<HpkeSenderContext>,
    ): Crypto["setupHpkeSender"] {
        return async (pub, info) => {
            const ctx = await inner.setupHpkeSender(pub, info);
            return {
                ...ctx,
                ...change(ctx),
                destroy: () => {
                    ctx.destroy();
                },
            };
        };
    }

    const cases: [string, Patch, string][] = [
        [
            "setupHpkeSender rejecting UNSUPPORTED",
            () => ({ setupHpkeSender: () => Promise.reject(new CapabilityError("UNSUPPORTED")) }),
            "UNSUPPORTED",
        ],
        [
            "seal rejecting UNSUPPORTED_ALGORITHM",
            (inner) => ({
                setupHpkeSender: senderWith(inner, () => ({
                    seal: () => Promise.reject(new CapabilityError("UNSUPPORTED_ALGORITHM")),
                })),
            }),
            "UNSUPPORTED_ALGORITHM",
        ],
        [
            "sha256 rejecting UNSUPPORTED",
            () => ({ sha256: () => Promise.reject(new CapabilityError("UNSUPPORTED")) }),
            "UNSUPPORTED",
        ],
        [
            "sha256 returning 31 bytes (note 5: hpkeInfo INVALID_RESPONSE)",
            () => ({ sha256: () => Promise.resolve(new Uint8Array(31)) }),
            "INVALID_RESPONSE",
        ],
        [
            "export returning 16 bytes",
            (inner) => ({
                setupHpkeSender: senderWith(inner, (ctx) => ({
                    export: async (label, length) => (await ctx.export(label, length)).slice(0, 16),
                })),
            }),
            "INVALID_RESPONSE",
        ],
        [
            "an encapsulated key of 31 bytes",
            (inner) => ({
                setupHpkeSender: senderWith(inner, (ctx) => ({
                    encapsulatedKey: ctx.encapsulatedKey.slice(0, 31),
                })),
            }),
            "INVALID_RESPONSE",
        ],
        [
            "randomBytes throwing UNAVAILABLE",
            () => ({
                randomBytes: () => {
                    throw new CapabilityError("UNAVAILABLE");
                },
            }),
            "UNAVAILABLE",
        ],
        [
            "randomBytes returning short output",
            (inner) => ({ randomBytes: (n) => inner.randomBytes(n).slice(0, n - 1) }),
            "INVALID_RESPONSE",
        ],
        [
            "randomBytes(16) returning 15 bytes",
            (inner) => ({ randomBytes: (n) => inner.randomBytes(n).slice(0, n === 16 ? 15 : n) }),
            "INVALID_RESPONSE",
        ],
        [
            "setupHpkeSender throwing a non-capability error",
            () => ({ setupHpkeSender: () => Promise.reject(new TypeError("adapter bug")) }),
            "INVALID_RESPONSE",
        ],
    ];

    it.each(cases)(
        "maps %s to CRYPTO_UNAVAILABLE and sends nothing",
        async (_name, patch, detail) => {
            const inner = workload.crypto;
            const client = new ChannelClient(
                clientConfig(workload, clock, { crypto: { ...inner, ...patch(inner) } }),
            );
            const cs = new Uint8Array(32).fill(7);
            const error = await failure(client.open(openSession(cs)));
            expect([error.code, error.detail]).toEqual(["CRYPTO_UNAVAILABLE", detail]);
            expect(workload.posts).toHaveLength(0);
            expect(zeroed(cs)).toBe(true);
        },
    );

    it("destroys the HPKE context when sealing fails", async () => {
        const spy = senderSpy({
            ...workload.crypto,
            setupHpkeSender: senderWith(workload.crypto, () => ({
                seal: () => Promise.reject(new CapabilityError("UNSUPPORTED")),
            })),
        });
        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        await failure(client.open({ op: "enroll" }));
        expect(spy.destroyed).toEqual([0]);
    });
});

describe("constructor validation (TypeError INVALID_CONFIG)", () => {
    it.each(["trustProfile", "transport", "crypto", "fetcher", "securityEvents", "clock"])(
        "refuses a configuration without %s, or with it null",
        (name) => {
            const base = clientConfig(workload, clock) as unknown as Record<string, unknown>;
            const without = Object.fromEntries(Object.entries(base).filter(([k]) => k !== name));
            for (const config of [without, { ...base, [name]: null }, { ...base, [name]: 1 }]) {
                expect(() => new ChannelClient(config as unknown as ChannelClientConfig)).toThrow(
                    new TypeError("INVALID_CONFIG"),
                );
            }
        },
    );

    it("accepts a configuration without limits (defaults) and with valid limits", () => {
        const { limits, ...rest } = clientConfig(workload, clock);
        expect(limits).toBeDefined();
        expect(() => new ChannelClient(rest)).not.toThrow();
        expect(() => new ChannelClient({ ...rest, limits: TEST_LIMITS })).not.toThrow();
    });

    const LEAVES: readonly (readonly string[])[] = [
        ["maxBundles"],
        ["bundle", "decode", "maxBytes"],
        ["bundle", "decode", "maxDepth"],
        ["bundle", "decode", "maxItems"],
        ["bundle", "maxPrekeys"],
        ["verifier", "maxTokenBytes"],
        ["verifier", "maxDiscoveryBytes"],
        ["verifier", "maxJwksBytes"],
        ["envelopeDecode", "maxBytes"],
        ["envelopeDecode", "maxDepth"],
        ["envelopeDecode", "maxItems"],
        ["aadDecode", "maxBytes"],
        ["aadDecode", "maxDepth"],
        ["aadDecode", "maxItems"],
        ["payloadDecode", "maxBytes"],
        ["payloadDecode", "maxDepth"],
        ["payloadDecode", "maxItems"],
        ["maxPayloadBytes"],
        ["responseTimeoutMs"],
        ["pollIntervalMs"],
        ["maxInFlight"],
        ["bundleMaxAgeMs"],
    ];

    function withLeaf(path: readonly string[], value: unknown): unknown {
        const copy = JSON.parse(JSON.stringify(TEST_LIMITS)) as Record<string, unknown>;
        let node = copy;
        for (const key of path.slice(0, -1)) {
            node = node[key] as Record<string, unknown>;
        }
        node[path[path.length - 1] as string] = value;
        return copy;
    }

    it("covers every leaf of ChannelLimits", () => {
        const leaves: string[] = [];
        const walk = (node: unknown, path: string[]): void => {
            if (typeof node === "object" && node !== null) {
                for (const [k, v] of Object.entries(node)) {
                    walk(v, [...path, k]);
                }
            } else {
                leaves.push(path.join("."));
            }
        };
        walk(TEST_LIMITS, []);
        expect(leaves.sort()).toEqual(LEAVES.map((p) => p.join(".")).sort());
    });

    it.each(LEAVES.map((p) => [p.join("."), p] as const))(
        "refuses limits whose %s is not a positive safe integer",
        (_name, path) => {
            for (const bad of [0, -1, 1.5, Number.NaN, Infinity, 2 ** 53, "8", undefined, null]) {
                const limits = withLeaf(path, bad) as ChannelLimits;
                expect(() => new ChannelClient(clientConfig(workload, clock, { limits }))).toThrow(
                    new TypeError("INVALID_CONFIG"),
                );
            }
        },
    );

    it.each(["bundle", "verifier", "envelopeDecode", "aadDecode", "payloadDecode"])(
        "refuses limits whose %s group is missing",
        (group) => {
            const limits = { ...TEST_LIMITS, [group]: undefined };
            expect(() => new ChannelClient(clientConfig(workload, clock, { limits }))).toThrow(
                new TypeError("INVALID_CONFIG"),
            );
        },
    );

    it("refuses non-object limits and a non-object config", () => {
        const limits = 5 as unknown as ChannelLimits;
        expect(() => new ChannelClient(clientConfig(workload, clock, { limits }))).toThrow(
            new TypeError("INVALID_CONFIG"),
        );
        expect(() => new ChannelClient(null as unknown as ChannelClientConfig)).toThrow(
            new TypeError("INVALID_CONFIG"),
        );
    });

    it("snapshots the capabilities: replacing one on the config object later has no effect", async () => {
        const config = { ...clientConfig(workload, clock) };
        const client = new ChannelClient(config);
        const other = new FakeWorkload(fx);
        other.listFailure = new Error("the replaced transport must not be used");
        (config as { transport: unknown }).transport = other;
        await client.open(openSession());
        expect(other.posts).toHaveLength(0);
        expect(workload.posts).toHaveLength(1);
    });

    it("snapshots the limits: a later change by the host has no effect", async () => {
        const limits = JSON.parse(JSON.stringify(TEST_LIMITS)) as { responseTimeoutMs: number };
        const client = new ChannelClient(
            clientConfig(workload, clock, { limits: limits as unknown as ChannelLimits }),
        );
        limits.responseTimeoutMs = 1;
        workload.onOpen = () => ({ kind: "silent" });
        const started = clock.now();
        expect((await failure(client.open(openSession()))).code).toBe("TIMEOUT");
        expect(clock.now() - started).toBeGreaterThanOrEqual(TEST_LIMITS.responseTimeoutMs);
    });
});

describe("open argument validation (INVALID_ARGUMENT before anything is fetched)", () => {
    const base = openSession();
    it.each([
        ["an upper-case client id", { ...base, clientId: "C1".repeat(16) }],
        ["a short client id", { ...base, clientId: "c1".repeat(15) }],
        ["a non-string client id", { ...base, clientId: 7 }],
        ["a 31-byte cs", { ...base, cs: new Uint8Array(31) }],
        ["a 15-byte key id", { ...base, keyId: new Uint8Array(15) }],
        ["a negative epoch", { ...base, epoch: -1 }],
        ["an epoch above uint32", { ...base, epoch: 2 ** 32 }],
        ["an unknown op", { op: "rotate" }],
    ])("refuses %s", async (_name, payload) => {
        const client = new ChannelClient(clientConfig(workload, clock));
        const error = await failure(client.open(payload as unknown as OpenPayload));
        expect(error.code).toBe("INVALID_ARGUMENT");
        expect(verifyBundle).not.toHaveBeenCalled();
        expect(workload.posts).toHaveLength(0);
    });
});

describe("bundle choice", () => {
    function scripted(inner: Crypto, script: Uint8Array[]): Crypto {
        return {
            ...inner,
            randomBytes: (n) => {
                const next = n === 4 ? script.shift() : undefined;
                return next ?? inner.randomBytes(n);
            },
        };
    }

    it("picks a fetched bundle uniformly, redrawing a draw in the biased tail", async () => {
        const fixtures = [
            fx,
            await instanceFixture("d1".repeat(16)),
            await instanceFixture("d2".repeat(16)),
        ];
        workload = new FakeWorkload(...fixtures);
        serveBundles(...fixtures);
        const script = [new Uint8Array([0xff, 0xff, 0xff, 0xff]), new Uint8Array([0, 0, 0, 5])];
        const client = new ChannelClient(
            clientConfig(workload, clock, { crypto: scripted(workload.crypto, script) }),
        );
        const { session } = await client.open(openSession());
        expect(session.instanceId).toBe("d2".repeat(16));
        expect(script).toHaveLength(0);
    });

    it("spreads opens over every verified bundle", async () => {
        const fixtures = [
            fx,
            await instanceFixture("d1".repeat(16)),
            await instanceFixture("d2".repeat(16)),
        ];
        workload = new FakeWorkload(...fixtures);
        serveBundles(...fixtures);
        const seen = new Map<string, number>();
        for (let i = 0; i < 60; i += 1) {
            const client = new ChannelClient(clientConfig(workload, clock));
            const { session } = await client.open(openSession());
            seen.set(session.instanceId, (seen.get(session.instanceId) ?? 0) + 1);
        }
        expect([...seen.keys()].sort()).toEqual(fixtures.map((f) => f.instanceId).sort());
    });
});
