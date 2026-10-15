// T-38 / ADR 0013 S1: ChannelClient hands verifyBundle a clock that is read at verification, after the bundle
// fetch, and never captured once per client or per open. verifyBundle is module-mocked (A1, TL-12).
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { BundleDeps } from "../../src/bundle/types.js";
import { verifyBundle } from "../../src/bundle/verify.js";
import type { PublishedBundle } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import {
    CLIENT,
    FakeClock,
    FakeWorkload,
    brandedBundle,
    clientConfig,
    instanceFixture,
    type InstanceFixture,
} from "./support.js";

vi.mock("../../src/bundle/verify.js", () => ({ verifyBundle: vi.fn() }));

// listBundles advances the clock, as a slow transport would, and records the time at which the fetch completed.
class SlowListWorkload extends FakeWorkload {
    readonly fetchedAt: number[] = [];

    constructor(
        private readonly clock: FakeClock,
        fx: InstanceFixture,
    ) {
        super(fx);
    }

    override listBundles(): Promise<readonly PublishedBundle[]> {
        this.clock.t += 7_000;
        this.fetchedAt.push(this.clock.t);
        return super.listBundles();
    }
}

function openSession() {
    return {
        op: "open_session" as const,
        clientId: CLIENT,
        cs: new Uint8Array(32).fill(7),
        keyId: new Uint8Array(16).fill(3),
        epoch: 4,
    };
}

let clock: FakeClock;
let fx: InstanceFixture;
let verifiedAt: number[];
let verifierDeps: BundleDeps[];

beforeEach(async () => {
    vi.mocked(verifyBundle).mockReset();
    clock = new FakeClock();
    fx = await instanceFixture();
    verifiedAt = [];
    verifierDeps = [];
    vi.mocked(verifyBundle).mockImplementation((_published, _profile, _events, deps) => {
        verifierDeps.push(deps);
        verifiedAt.push(deps.now());
        return Promise.resolve(brandedBundle(fx, deps.now()));
    });
});

describe("ChannelClient: the verifier's clock is read fresh (T-38 S1, criterion 12)", () => {
    it("reads now after each bundle fetch, on every open, and keeps no captured value", async () => {
        const workload = new SlowListWorkload(clock, fx);
        const client = new ChannelClient(clientConfig(workload, clock));

        await client.open(openSession());
        clock.t += 1_000;
        await client.open(openSession());

        expect(workload.fetchedAt).toHaveLength(2);
        expect(verifiedAt).toEqual(workload.fetchedAt);
        expect(verifiedAt[0]).not.toBe(verifiedAt[1]);
        expect(verifierDeps[0]?.now()).toBe(clock.now());
    });
});
