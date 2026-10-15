// T-26 ChannelClient open flow (INC-2-API §7.4 steps (1)–(7); FR-4; SR-1 B-13, SR-4, SR-14 R-4).
// verifyBundle is module-mocked (A1, TL-12); the fake workload answers through the fake Transport.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { BundleError, createVerifiedBundle, type VerifiedBundle } from "../../src/bundle/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import { CapabilityError } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError } from "../../src/channel/errors.js";
import {
    CLIENT,
    FakeClock,
    ROUTE_PATTERN,
    TEST_LIMITS,
    asMap,
    decode,
    hex,
    map,
    FakeWorkload,
    brandedBundle,
    clientConfig,
    instanceFixture,
    senderSpy,
    zeroed,
    type InstanceFixture,
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
