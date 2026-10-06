// Contract: Core bundle and channel-client boundary (FR-4, SR-1 B-13, SR-3, SR-14; INC-2-API §7.1–§7.5;
// API-TL §3). Expected red until T-15, T-16, T-17 and T-26 merge (docs/tasks/INC-2/WAVES.md).
import { describe, expect, it } from "vitest";

import {
    BundleError,
    ChannelClient,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    Session,
    encodeCanonical,
    selectPreKey,
    verifyBundle,
    type CanonicalValue,
    type ChannelClientConfig,
    type Clock,
    type SecurityEvent,
    type Transport,
    type VerifiedAttestation,
    type VerifiedBundle,
} from "@teecustody/core";
import { createWebCrypto } from "@teecustody/web";

import { createVerifiedBundle } from "../../../packages/teecustody-core/src/bundle/types.js";
import { fixtureFetcher } from "../../support/fixture-fetcher.js";
import { buildFixture, IMAGE_DIGEST, NOW_MS } from "../../support/token-factory.js";

const INSTANCE = "a1".repeat(16);
const CLIENT = "c1".repeat(16);

const silentTransport: Transport = {
    listBundles: () => Promise.resolve([]),
    postRequest: () => Promise.reject(new Error("not expected")),
    getResponses: () => Promise.resolve({ responses: [], next: undefined }),
};

const fixedClock: Clock = { now: () => NOW_MS, sleep: () => Promise.resolve() };

async function config(transport: Transport = silentTransport): Promise<ChannelClientConfig> {
    const fixture = await buildFixture();
    const events: SecurityEvent[] = [];
    return {
        trustProfile: fixture.profile,
        transport,
        crypto: createWebCrypto(),
        fetcher: fixtureFetcher(fixture.http),
        securityEvents: {
            report: (event) => {
                events.push(event);
                return Promise.resolve();
            },
        },
        clock: fixedClock,
    };
}

function attestationLiteral(): VerifiedAttestation {
    return {
        issuer: "https://issuer.contract.test",
        audience: "https://contract.teecustody.test/tee",
        imageDigest: IMAGE_DIGEST,
        signerKeyIds: [],
        hwmodel: "CONTRACT_TEST_HW",
        issuedAtMs: NOW_MS - 60_000,
        expiresAtMs: NOW_MS + 3_540_000,
    } as unknown as VerifiedAttestation;
}

function bundleFields(attestation: VerifiedAttestation): VerifiedBundle {
    return {
        instanceId: INSTANCE,
        identityPublicKey: new Uint8Array(32),
        attestation,
        prekeys: [
            { id: 1, publicKey: new Uint8Array(32), notAfterMs: NOW_MS + 5_000 },
            { id: 2, publicKey: new Uint8Array(32), notAfterMs: NOW_MS + 5_001 },
            { id: 3, publicKey: new Uint8Array(32), notAfterMs: NOW_MS + 3_600_000 },
        ],
        verifiedAtMs: NOW_MS,
    } as unknown as VerifiedBundle;
}

describe("Core channel contract", () => {
    it("pins the default channel limits and freezes them", () => {
        expect(DEFAULT_CHANNEL_LIMITS).toEqual({
            maxBundles: 16,
            bundle: { decode: { maxBytes: 65_536, maxDepth: 4, maxItems: 4096 }, maxPrekeys: 256 },
            verifier: { maxTokenBytes: 16_384, maxDiscoveryBytes: 65_536, maxJwksBytes: 65_536 },
            envelopeDecode: { maxBytes: 65_536, maxDepth: 2, maxItems: 16 },
            aadDecode: { maxBytes: 512, maxDepth: 2, maxItems: 16 },
            payloadDecode: { maxBytes: 32_768, maxDepth: 16, maxItems: 4096 },
            maxPayloadBytes: 32_768,
            responseTimeoutMs: 30_000,
            pollIntervalMs: 500,
            maxInFlight: 8,
            bundleMaxAgeMs: 60_000,
        });
        expect(Object.isFrozen(DEFAULT_CHANNEL_LIMITS)).toBe(true);
        expect(Object.isFrozen(DEFAULT_CHANNEL_LIMITS.bundle.decode)).toBe(true);
    });

    it("carries only the code in channel and bundle errors", () => {
        const channel = new ChannelError("REMOTE_ERROR", "AUTHENTICATION_FAILED");
        const bundle = new BundleError("ATTESTATION_FAILED", "nonce");
        expect([channel.message, channel.code, channel.detail]).toEqual([
            "REMOTE_ERROR",
            "REMOTE_ERROR",
            "AUTHENTICATION_FAILED",
        ]);
        expect([bundle.message, bundle.attestationCheck]).toEqual(["ATTESTATION_FAILED", "nonce"]);
    });

    it("rejects malformed bundles and a mismatched instance before any fetch", async () => {
        const base = await config();
        const fetcher = fixtureFetcher(new Map());
        const deps = {
            crypto: createWebCrypto(),
            fetcher,
            now: () => NOW_MS,
            verifierLimits: DEFAULT_CHANNEL_LIMITS.verifier,
            bundleLimits: DEFAULT_CHANNEL_LIMITS.bundle,
        };
        const events = base.securityEvents;
        const wellFormed = encodeCanonical(
            new Map<string, CanonicalValue>([
                ["instance_id", "b2".repeat(16)],
                ["token", "a.b.c"],
                ["IK_pub", new Uint8Array(32)],
                ["published_at", NOW_MS / 1000],
                [
                    "prekeys",
                    [
                        new Map<string, CanonicalValue>([
                            ["id", 1],
                            ["pub", new Uint8Array(32)],
                            ["not_after", NOW_MS / 1000 + 3600],
                            ["sig", new Uint8Array(64)],
                        ]),
                    ],
                ],
            ]),
        );

        await expect(
            verifyBundle(
                { instanceId: INSTANCE, bundle: new Uint8Array([0xa0]) },
                base.trustProfile,
                events,
                deps,
            ),
        ).rejects.toMatchObject({ code: "MALFORMED" });
        await expect(
            verifyBundle(
                { instanceId: INSTANCE, bundle: wellFormed },
                base.trustProfile,
                events,
                deps,
            ),
        ).rejects.toMatchObject({ code: "INSTANCE_MISMATCH" });
        expect(fetcher.calls).toEqual([]);
    });

    it("refuses an unbranded bundle or attestation in open (B-13)", async () => {
        const client = new ChannelClient(await config());
        const payload = {
            op: "open_session",
            clientId: CLIENT,
            cs: new Uint8Array(32),
            keyId: new Uint8Array(16),
            epoch: 0,
        } as const;

        await expect(
            client.open(payload, bundleFields(attestationLiteral())),
        ).rejects.toMatchObject({ code: "UNVERIFIED_BUNDLE" });
        await expect(
            client.open(payload, createVerifiedBundle(bundleFields(attestationLiteral()))),
        ).rejects.toMatchObject({ code: "UNVERIFIED_BUNDLE" });
    });

    it("selects only unused pre-keys valid beyond the 5 s margin", () => {
        const bundle = createVerifiedBundle(bundleFields(attestationLiteral()));
        const crypto = createWebCrypto();
        const seen = new Set<number>();
        for (let i = 0; i < 200; i += 1) {
            const key = selectPreKey(bundle, new Set([3]), NOW_MS, crypto);
            if (key !== undefined) {
                seen.add(key.id);
            }
        }
        expect([...seen].sort()).toEqual([2]);
        expect(selectPreKey(bundle, new Set([2, 3]), NOW_MS, crypto)).toBeUndefined();
    });

    it("rejects a config without a capability and exposes no sealing parameter", async () => {
        const { crypto, ...rest } = await config();
        expect(crypto).toBeDefined();
        expect(() => new ChannelClient(rest as unknown as ChannelClientConfig)).toThrow(
            "INVALID_CONFIG",
        );
        expect(Session.prototype.request.length).toBe(2);
    });
});
