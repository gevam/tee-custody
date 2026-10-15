// T-26 ChannelClient open flow (INC-2-API §7.4 steps (1)–(7); FR-4; SR-1 B-13, SR-4, SR-14 R-4).
// verifyBundle is module-mocked (A1, TL-12); the fake workload answers through the fake Transport.
import { beforeEach, describe, expect, it, vi } from "vitest";

import { verifyBundle } from "../../src/bundle/verify.js";
import { ChannelClient } from "../../src/channel/client.js";
import { ChannelError } from "../../src/channel/errors.js";
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
        expect([...(seen?.plaintext.keys() ?? [])].sort()).toEqual([
            "cs",
            "epoch",
            "key_id",
            "op",
        ]);
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
