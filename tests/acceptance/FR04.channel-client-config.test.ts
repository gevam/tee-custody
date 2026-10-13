// FR-4 / SR-1 / B-13: ChannelClient construction and fail-closed bundle handling, without a live
// workload (INC-2-API 7.4). Profiles come only from the shared fixture builder (TL-12).
//
// Owning task: T-26 (ChannelClient); T-16 for the bundle verification it relies on.
// Expected failure on trunk: Error("NOT_IMPLEMENTED: T-26") from the ChannelClient constructor.
import {
    CapabilityError,
    ChannelClient,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    type Bytes,
    type ChannelClientConfig,
    type PublishedBundle,
    type ResponsePage,
    type Transport,
} from "@teecustody/core";
import { beforeEach, describe, expect, it } from "vitest";

import { expectThrown } from "./e2e-support.js";

import { testChannelCrypto } from "../../packages/teecustody-core/test/support/channel-crypto.js";

import { MemorySink, sharedFixture } from "./support.js";

class SpyTransport implements Transport {
    readonly posts: { instance: string; body: Bytes }[] = [];
    list: () => Promise<readonly PublishedBundle[]> = () => Promise.resolve([]);

    listBundles(): Promise<readonly PublishedBundle[]> {
        return this.list();
    }
    postRequest(instance: string, body: Bytes): Promise<string> {
        this.posts.push({ instance, body });
        return Promise.resolve("00".repeat(16));
    }
    getResponses(): Promise<ResponsePage> {
        return Promise.resolve({ responses: [], next: undefined });
    }
}

let transport: SpyTransport;
let base: ChannelClientConfig;

beforeEach(async () => {
    const fx = await sharedFixture();
    transport = new SpyTransport();
    base = {
        trustProfile: fx.profile,
        transport,
        crypto: testChannelCrypto(),
        fetcher: { get: () => Promise.reject(new CapabilityError("UNAVAILABLE")) },
        securityEvents: new MemorySink(),
        clock: { now: () => Date.now(), sleep: (ms) => new Promise((r) => setTimeout(r, ms)) },
    };
});

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function code(error: unknown): string {
    return error instanceof ChannelError ? error.code : `not a ChannelError: ${String(error)}`;
}

describe("FR-4 ChannelClient configuration is validated", () => {
    it("accepts a complete configuration with default limits", () => {
        expect(() => new ChannelClient(base)).not.toThrow();
    });

    it.each(["trustProfile", "transport", "crypto", "fetcher", "securityEvents", "clock"] as const)(
        "refuses a configuration without %s (TypeError INVALID_CONFIG)",
        (missing) => {
            const config = Object.fromEntries(
                Object.entries(base).filter(([key]) => key !== missing),
            );
            expectThrown(
                () => new ChannelClient(config as unknown as ChannelClientConfig),
                new TypeError("INVALID_CONFIG"),
            );
        },
    );

    it.each([
        ["zero response timeout", { responseTimeoutMs: 0 }],
        ["negative in-flight bound", { maxInFlight: -1 }],
        ["fractional poll interval", { pollIntervalMs: 1.5 }],
        ["NaN bundle age", { bundleMaxAgeMs: Number.NaN }],
        ["non-safe payload bound", { maxPayloadBytes: Number.MAX_SAFE_INTEGER + 2 }],
    ])("refuses limits with a %s", (_name, override) => {
        const limits = { ...DEFAULT_CHANNEL_LIMITS, ...override };
        expectThrown(() => new ChannelClient({ ...base, limits }), new TypeError("INVALID_CONFIG"));
    });
});

describe("SR-1 ChannelClient never trusts an unverified bundle", () => {
    it("fails with NO_VERIFIED_BUNDLE when the relay lists nothing", async () => {
        const client = new ChannelClient(base);
        expect(code(await failure(client.fetchVerifiedBundles()))).toBe("NO_VERIFIED_BUNDLE");
    });

    it("discards garbage bundles and fails with NO_VERIFIED_BUNDLE rather than throwing their errors", async () => {
        transport.list = () =>
            Promise.resolve([
                { instanceId: "ab".repeat(16), bundle: new Uint8Array([0xff, 0x00]) },
                { instanceId: "cd".repeat(16), bundle: new Uint8Array(1000).fill(7) },
                { instanceId: "ef".repeat(16), bundle: new Uint8Array(0) },
            ]);
        const client = new ChannelClient(base);
        expect(code(await failure(client.fetchVerifiedBundles()))).toBe("NO_VERIFIED_BUNDLE");
    });

    it("reports a transport failure as TRANSPORT with the capability code", async () => {
        transport.list = () => Promise.reject(new CapabilityError("UNAVAILABLE"));
        const client = new ChannelClient(base);
        const error = await failure(client.fetchVerifiedBundles());
        expect(code(error)).toBe("TRANSPORT");
        expect((error as ChannelError).detail).toBe("UNAVAILABLE");
    });

    it("refuses a structurally identical but unbranded bundle literal and sends nothing", async () => {
        const client = new ChannelClient(base);
        const forged = {
            instanceId: "ab".repeat(16),
            identityPublicKey: new Uint8Array(32),
            attestation: { imageDigest: `sha256:${"ab".repeat(32)}` },
            prekeys: [{ id: 0, publicKey: new Uint8Array(32), notAfterMs: Date.now() + 3_600_000 }],
            verifiedAtMs: Date.now(),
        };
        const error = await failure(
            client.open(
                { op: "enroll" },
                forged as unknown as Parameters<ChannelClient["open"]>[1],
            ),
        );
        expect(code(error)).toBe("UNVERIFIED_BUNDLE");
        expect(transport.posts).toHaveLength(0);
    });

    it("never falls back to sending anything when no bundle verifies", async () => {
        const client = new ChannelClient(base);
        expect(code(await failure(client.open({ op: "enroll" })))).toBe("NO_VERIFIED_BUNDLE");
        expect(transport.posts).toHaveLength(0);
    });
});
