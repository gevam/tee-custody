// T-26 criterion 13 (A2; INC-2-API §7.1/§7.2 ruling): open reads IK_pub and the selected pre-key's public key
// exactly once each, into locals, and uses only those. isVerifiedBundle is wrapped so that a test bundle with
// counting getters is accepted; every other bundle still needs the real brand. verifyBundle is never reached.
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as bundleTypes from "../../src/bundle/types.js";
import type { VerifiedBundle } from "../../src/bundle/types.js";
import type { Bytes } from "../../src/capabilities.js";
import { ChannelClient } from "../../src/channel/client.js";
import {
    CLIENT,
    FakeClock,
    FakeWorkload,
    attestationAt,
    brandedBundle,
    clientConfig,
    instanceFixture,
    referenceInfo,
    senderSpy,
    type InstanceFixture,
} from "./support.js";

const testBranded = new WeakSet();

vi.mock("../../src/bundle/verify.js", () => ({ verifyBundle: vi.fn() }));
vi.mock("../../src/bundle/types.js", async (importOriginal) => {
    const actual = await importOriginal<typeof bundleTypes>();
    return {
        ...actual,
        isVerifiedBundle: (v: unknown) =>
            actual.isVerifiedBundle(v) ||
            (typeof v === "object" && v !== null && testBranded.has(v)),
    };
});

let clock: FakeClock;
let fx: InstanceFixture;
let workload: FakeWorkload;

beforeEach(async () => {
    clock = new FakeClock();
    fx = await instanceFixture(undefined, [7]);
    workload = new FakeWorkload(fx);
});

function openSession() {
    return {
        op: "open_session" as const,
        clientId: CLIENT,
        cs: new Uint8Array(32).fill(5),
        keyId: new Uint8Array(16),
        epoch: 1,
    };
}

interface Counted {
    readonly bundle: VerifiedBundle;
    readonly reads: { identityPublicKey: number; publicKey: number };
}

// A bundle whose key getters count their reads and return attacker bytes after the first read.
function countedBundle(): Counted {
    const reads = { identityPublicKey: 0, publicKey: 0 };
    const prekey = fx.prekeys[0];
    if (prekey === undefined) {
        throw new Error("fixture: no pre-key");
    }
    const hostile = new Uint8Array(32).fill(0xee);
    const entry = {
        id: prekey.id,
        notAfterMs: prekey.notAfterMs,
        get publicKey(): Bytes {
            reads.publicKey += 1;
            return reads.publicKey === 1 ? prekey.pair.publicKey.slice() : hostile.slice();
        },
    };
    const bundle = {
        instanceId: fx.instanceId,
        attestation: attestationAt(clock.now()),
        prekeys: Object.freeze([entry]),
        verifiedAtMs: clock.now(),
        get identityPublicKey(): Bytes {
            reads.identityPublicKey += 1;
            return reads.identityPublicKey === 1 ? fx.ikPub.slice() : hostile.slice();
        },
    };
    testBranded.add(bundle);
    return { bundle: bundle as unknown as VerifiedBundle, reads };
}

describe("criterion 13: each key is read once into a local (A2)", () => {
    it("uses the original keys when the host mutates its read copies before open", async () => {
        const spy = senderSpy(workload.crypto);
        const bundle = brandedBundle(fx, clock.now());
        expect(bundleTypes.isVerifiedBundle(bundle)).toBe(true);
        bundle.identityPublicKey.fill(0xaa);
        bundle.prekeys[0]?.publicKey.fill(0xbb);

        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        await client.open(openSession(), bundle);

        expect(spy.setups).toHaveLength(1);
        expect(spy.setups[0]?.publicKey).toEqual(fx.prekeys[0]?.pair.publicKey);
        expect(spy.setups[0]?.info).toEqual(await referenceInfo(fx.ikPub, 7));
        expect(workload.opens).toHaveLength(1);
    });

    it("reads identityPublicKey and the selected publicKey exactly once per open", async () => {
        const spy = senderSpy(workload.crypto);
        const { bundle, reads } = countedBundle();
        const client = new ChannelClient(clientConfig(workload, clock, { crypto: spy.crypto }));
        await client.open(openSession(), bundle);

        expect(reads).toEqual({ identityPublicKey: 1, publicKey: 1 });
        expect(spy.setups[0]?.publicKey).toEqual(fx.prekeys[0]?.pair.publicKey);
        expect(spy.setups[0]?.info).toEqual(await referenceInfo(fx.ikPub, 7));
        expect(workload.opens).toHaveLength(1);
    });
});
