// FR-4 / FR-5 / SR-1 / SR-14: the TypeScript client against the live Python workload through the
// reference gateway (end-to-end harness, TL-8). The client composition is the one a browser host uses:
// web adapters (createWebCrypto, FetchFetcher, FetchTransport) under Core's ChannelClient.
//
// Owning tasks: T-31 (harness; its absence is the current red reason: HARNESS_MISSING), then T-14,
// T-16, T-17, T-18, T-19, T-22, T-23, T-24, T-26, T-28, T-29, T-33/T-21 (v2 profile, MU-1).
// Expected failure on trunk: Error("HARNESS_MISSING: tests/e2e/channel_harness.py (T-31)").
import {
    AttestationError,
    CapabilityError,
    ChannelClient,
    DEFAULT_CHANNEL_LIMITS,
    ChannelError,
    decodeCanonical,
    encodeCanonical,
    verifyAttestation,
    type CanonicalValue,
    type PublishedBundle,
    type ResponsePage,
    type Session,
    type Transport,
} from "@teecustody/core";
import { FetchFetcher, createWebCrypto } from "@teecustody/web";
import { afterAll, describe, expect, it, vi } from "vitest";

import {
    FAST_LIMITS,
    bytesToHex,
    clientParts,
    hexToBytes,
    sharedHarness,
    withBundleDiagnostics,
    type Harness,
    type TestClientParts,
} from "./e2e-support.js";

vi.setConfig({ testTimeout: 120_000, hookTimeout: 120_000 });
const harness = sharedHarness();
afterAll(async () => {
    await harness.stop();
});

const echo = (n: number): ReadonlyMap<string, CanonicalValue> => new Map([["n", n]]);

async function connect(
    h: Harness,
    parts: TestClientParts = clientParts(h),
): Promise<{ client: ChannelClient; session: Session; parts: TestClientParts }> {
    const client = new ChannelClient(parts.config);
    const { session } = await withBundleDiagnostics(
        h,
        parts,
        client.open({
            op: "open_session",
            clientId: h.fixture.client_id,
            cs: hexToBytes(h.fixture.cs),
            keyId: hexToBytes(h.fixture.key_id),
            epoch: h.fixture.epoch,
        }),
    );
    return { client, session, parts };
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function expectChannelError(error: unknown, code: string, detail?: string): void {
    expect(error).toBeInstanceOf(ChannelError);
    const e = error as ChannelError;
    expect(e.code).toBe(code);
    if (detail !== undefined) {
        expect(e.detail).toBe(detail);
    }
}

/** TRANSPORT/UNAVAILABLE (flaky post or the gateway's back-pressure) or TIMEOUT (seq order, Q8). */
function expectContracted(error: unknown): void {
    expect(error).toBeInstanceOf(ChannelError);
    const e = error as ChannelError;
    const outcome = e.detail === undefined ? e.code : `${e.code}/${e.detail}`;
    expect(["TIMEOUT", "TRANSPORT", "TRANSPORT/UNAVAILABLE"]).toContain(outcome);
}

describe("FR-4 session over the gateway", () => {
    it("opens a session, round-trips an authenticated request, closes, and refuses use after close", async () => {
        // Given the live workload and gateway
        const h = await harness.get();
        // When the client opens a session with the fixture share and sends an echo request
        const { session } = await connect(h);
        const answer = await session.request("test.echo", echo(7));
        // Then the authenticated response carries the echoed payload
        expect(answer).toBeInstanceOf(Map);
        expect((answer as Map<string, CanonicalValue>).get("n")).toBe(7);
        expect(session.clientId).toBe(h.fixture.client_id);
        expect(session.sessionId).toHaveLength(16);
        // When the session is closed (twice), then further use is refused locally
        await session.close();
        await session.close();
        expect(session.closed).toBe(true);
        expectChannelError(await failure(session.request("test.echo", echo(1))), "SESSION_CLOSED");
    });

    it("keeps answering after a remote error for an unknown operation", async () => {
        const h = await harness.get();
        const { session } = await connect(h);
        // When an operation the handler does not know is requested
        const error = await failure(session.request("test.nothing", null));
        // Then the remote category is surfaced, and the session stays usable
        expectChannelError(error, "REMOTE_ERROR", "UNKNOWN_OPERATION");
        expect(await session.request("test.echo", echo(2))).toBeInstanceOf(Map);
        await session.close();
    });

    it("refuses an open with the wrong share, with an authenticated remote error", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const client = new ChannelClient(parts.config);
        const error = await failure(
            withBundleDiagnostics(
                h,
                parts,
                client.open({
                    op: "open_session",
                    clientId: h.fixture.client_id,
                    cs: new Uint8Array(32),
                    keyId: hexToBytes(h.fixture.key_id),
                    epoch: h.fixture.epoch,
                }),
            ),
        );
        expectChannelError(error, "REMOTE_ERROR", "AUTHENTICATION_FAILED");
    });

    it("refuses an open for a client id the workload does not know", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const client = new ChannelClient(parts.config);
        const error = await failure(
            withBundleDiagnostics(
                h,
                parts,
                client.open({
                    op: "open_session",
                    clientId: "ab".repeat(16),
                    cs: hexToBytes(h.fixture.cs),
                    keyId: hexToBytes(h.fixture.key_id),
                    epoch: h.fixture.epoch,
                }),
            ),
        );
        expectChannelError(error, "REMOTE_ERROR", "AUTHENTICATION_FAILED");
    });

    it("surfaces the workload's refusal of enrol (no custody in INC-2) as a remote error", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const client = new ChannelClient(parts.config);
        const error = await failure(withBundleDiagnostics(h, parts, client.open({ op: "enroll" })));
        expectChannelError(error, "REMOTE_ERROR", "UNKNOWN_OPERATION");
    });

    it("matches concurrent answers to their own requests and bounds the requests in flight", async () => {
        const h = await harness.get();
        const { session } = await connect(
            h,
            clientParts(h, { limits: { ...FAST_LIMITS, responseTimeoutMs: 3000 } }),
        );
        // When nine requests are started at once (maxInFlight is 8)
        const results = await Promise.allSettled(
            Array.from({ length: 9 }, (_, i) => session.request("test.echo", echo(i))),
        );
        // Then each of the first eight either resolves with its own payload or fails with a contracted
        // outcome (arrival order is not promised, Q8; the gateway caps in-flight per source, section 6)
        let fulfilled = 0;
        results.slice(0, 8).forEach((r, i) => {
            if (r.status === "fulfilled") {
                fulfilled += 1;
                expect((r.value as Map<string, CanonicalValue>).get("n")).toBe(i);
            } else {
                const e = r.reason as ChannelError;
                expect(e).toBeInstanceOf(ChannelError);
                const outcome = e.detail === undefined ? e.code : `${e.code}/${e.detail}`;
                expect(["TIMEOUT", "TRANSPORT", "TRANSPORT/UNAVAILABLE"]).toContain(outcome);
            }
        });
        expect(fulfilled).toBeGreaterThanOrEqual(1);
        // And the ninth is refused locally
        expect(results[8]?.status).toBe("rejected");
        expectChannelError((results[8] as PromiseRejectedResult).reason, "INVALID_ARGUMENT");
        // And the session still answers
        const after = await session.request("test.echo", echo(99));
        expect((after as Map<string, CanonicalValue>).get("n")).toBe(99);
        await session.close();
    });

    it("rejects invalid operation names, the reserved close, and oversize payloads before sending", async () => {
        const h = await harness.get();
        const { session } = await connect(h);
        for (const op of ["", "Test.Echo", "1abc", "a b", "close", "x".repeat(65)]) {
            expectChannelError(await failure(session.request(op, null)), "INVALID_ARGUMENT");
        }
        const big = new Uint8Array(40_000);
        expectChannelError(await failure(session.request("test.echo", big)), "INVALID_ARGUMENT");
        expect(await session.request("test.echo", echo(3))).toBeInstanceOf(Map);
        await session.close();
    });

    it("replaces an existing session of the same client; the old one gets no further answers", async () => {
        const h = await harness.get();
        // Given a first session and short timeouts
        const quick = { ...FAST_LIMITS, responseTimeoutMs: 1500 };
        const first = await connect(h, clientParts(h, { limits: quick }));
        // When the same client opens a second session
        const second = await connect(h);
        // Then the first is closed by the workload: its request times out; the second works
        expectChannelError(await failure(first.session.request("test.echo", echo(1))), "TIMEOUT");
        expect(await second.session.request("test.echo", echo(2))).toBeInstanceOf(Map);
        await second.session.close();
    });
});

describe("SR-14 client nonce discipline (live)", () => {
    it("never reuses an AES-GCM (key, nonce) and never lowers the counter, across failures and concurrency", async () => {
        const h = await harness.get();
        // Given a transport that rejects every fourth post (a transport failure the host may retry)
        let posts = 0;
        let flakyOn = true;
        const flaky = (inner: Transport): Transport => ({
            listBundles: () => inner.listBundles(),
            getResponses: (client, after) => inner.getResponses(client, after),
            postRequest: (instance, body) => {
                posts += 1;
                if (flakyOn && posts % 4 === 0) {
                    return Promise.reject(new CapabilityError("UNAVAILABLE"));
                }
                return inner.postRequest(instance, body);
            },
        });
        const parts = clientParts(h, {
            transport: flaky,
            limits: { ...FAST_LIMITS, responseTimeoutMs: 3000 },
        });
        const { session } = await connect(h, parts);
        // When requests are issued sequentially and in bursts of four, with host retries on failure
        for (let round = 0; round < 6; round += 1) {
            const burst = await Promise.allSettled(
                Array.from({ length: 4 }, (_, i) =>
                    session.request("test.echo", echo(round * 4 + i)),
                ),
            );
            for (const [i, r] of burst.entries()) {
                if (r.status === "rejected") {
                    expectContracted(r.reason);
                    // host retry = a new request(); it may itself hit the flaky transport
                    const [retry] = await Promise.allSettled([
                        session.request("test.echo", echo(100 + round * 4 + i)),
                    ]);
                    if (retry.status === "rejected") {
                        expectContracted(retry.reason);
                    }
                }
            }
        }
        flakyOn = false; // the close is not part of the failure pattern under test
        await session.close();
        // Then every (key, nonce) pair is unique, and per key the nonce counter only grows
        const seen = new Set<string>();
        const countersByKey = new Map<string, number[]>();
        for (const call of parts.spyCalls) {
            const id = `${call.keyHex}:${call.nonceHex}`;
            expect(seen.has(id)).toBe(false);
            seen.add(id);
            expect(call.nonceHex.slice(0, 8)).toBe("00000000");
            const list = countersByKey.get(call.keyHex) ?? [];
            list.push(Number(BigInt(`0x${call.nonceHex.slice(8)}`)));
            countersByKey.set(call.keyHex, list);
        }
        // And, per key, the counters used are exactly 0..n-1: allocated once each, never rolled back
        for (const list of countersByKey.values()) {
            expect([...list].sort((x, y) => x - y)).toEqual(list.map((_, i) => i));
        }
        expect(seen.size).toBeGreaterThanOrEqual(24);
    });
});

describe("SR-1 independent verification of an untrusted relay", () => {
    const tamper =
        (edit: (bundle: Map<string, CanonicalValue>) => void) =>
        (inner: Transport): Transport => ({
            postRequest: (instance, body) => inner.postRequest(instance, body),
            getResponses: (client, after) => inner.getResponses(client, after),
            listBundles: async (): Promise<readonly PublishedBundle[]> => {
                const real = await inner.listBundles();
                return real.map((p) => {
                    const decoded = decodeCanonical(p.bundle, DEFAULT_CHANNEL_LIMITS.bundle.decode);
                    const map = new Map(decoded as Map<string, CanonicalValue>);
                    edit(map);
                    return { instanceId: p.instanceId, bundle: encodeCanonical(map) };
                });
            },
        });

    it("discards a bundle whose identity key was swapped by the relay", async () => {
        const h = await harness.get();
        const swapped = tamper((b) => b.set("IK_pub", new Uint8Array(32).fill(7)));
        const client = new ChannelClient(clientParts(h, { transport: swapped }).config);
        expectChannelError(await failure(client.fetchVerifiedBundles()), "NO_VERIFIED_BUNDLE");
    });

    it("discards a bundle with a corrupted pre-key signature", async () => {
        const h = await harness.get();
        const corrupted = tamper((b) => {
            const keys = (b.get("prekeys") as CanonicalValue[]).map((entry) => {
                const copy = new Map(entry as Map<string, CanonicalValue>);
                const sig = new Uint8Array(copy.get("sig") as Uint8Array);
                sig[0] = (sig[0] ?? 0) ^ 1;
                copy.set("sig", sig);
                return copy;
            });
            b.set("prekeys", keys);
        });
        const client = new ChannelClient(clientParts(h, { transport: corrupted }).config);
        expectChannelError(await failure(client.fetchVerifiedBundles()), "NO_VERIFIED_BUNDLE");
    });

    it("fails closed when the relay publishes no bundle, and never falls back to an unverified one", async () => {
        const h = await harness.get();
        const none = (inner: Transport): Transport => ({
            postRequest: (instance, body) => inner.postRequest(instance, body),
            getResponses: (client, after) => inner.getResponses(client, after),
            listBundles: () => Promise.resolve([]),
        });
        const client = new ChannelClient(clientParts(h, { transport: none }).config);
        expectChannelError(await failure(client.fetchVerifiedBundles()), "NO_VERIFIED_BUNDLE");
        expectChannelError(await failure(client.open({ op: "enroll" })), "NO_VERIFIED_BUNDLE");
    });

    it("ignores junk and duplicated responses injected by the relay", async () => {
        const h = await harness.get();
        // Given a relay that prepends garbage and duplicates every real response
        const noisy = (inner: Transport): Transport => ({
            listBundles: () => inner.listBundles(),
            postRequest: (instance, body) => inner.postRequest(instance, body),
            getResponses: async (client, after): Promise<ResponsePage> => {
                const page = await inner.getResponses(client, after);
                const junk = {
                    requestId: "00".repeat(16),
                    body: new Uint8Array([0xff, 0x00, 0x01]),
                };
                return {
                    responses: [junk, ...page.responses, ...page.responses],
                    next: page.next,
                };
            },
        });
        const { session } = await connect(h, clientParts(h, { transport: noisy }));
        // Then requests still resolve exactly once with their own payloads
        for (let i = 0; i < 3; i += 1) {
            const answer = await session.request("test.echo", echo(i));
            expect((answer as Map<string, CanonicalValue>).get("n")).toBe(i);
        }
        await session.close();
    });

    it("never accepts a response whose ciphertext the relay altered (it times out instead)", async () => {
        const h = await harness.get();
        const flip = (inner: Transport): Transport => ({
            listBundles: () => inner.listBundles(),
            postRequest: (instance, body) => inner.postRequest(instance, body),
            getResponses: async (client, after): Promise<ResponsePage> => {
                const page = await inner.getResponses(client, after);
                return {
                    next: page.next,
                    responses: page.responses.map((r) => {
                        const body = new Uint8Array(r.body);
                        body[body.length - 1] = (body[body.length - 1] ?? 0) ^ 1;
                        return { requestId: r.requestId, body };
                    }),
                };
            },
        });
        const quick = { ...FAST_LIMITS, responseTimeoutMs: 1500 };
        const attackedParts = clientParts(h, { transport: flip, limits: quick });
        const attacked = new ChannelClient(attackedParts.config);
        // When every response is altered in transit, the open cannot complete
        const error = await failure(
            withBundleDiagnostics(
                h,
                attackedParts,
                attacked.open({
                    op: "open_session",
                    clientId: h.fixture.client_id,
                    cs: hexToBytes(h.fixture.cs),
                    keyId: hexToBytes(h.fixture.key_id),
                    epoch: h.fixture.epoch,
                }),
            ),
        );
        // Then no session is created: the client times out rather than trust unauthenticated data
        expectChannelError(error, "TIMEOUT");
    });

    it("rejects an unbranded (structurally identical) bundle literal before any request is sent", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const client = new ChannelClient(parts.config);
        const [real] = await withBundleDiagnostics(h, parts, client.fetchVerifiedBundles());
        expect(real).toBeDefined();
        // Given an object literal that copies every field of a genuine verified bundle
        const forged = {
            instanceId: real?.instanceId,
            identityPublicKey: real?.identityPublicKey,
            attestation: real?.attestation,
            prekeys: real?.prekeys,
            verifiedAtMs: real?.verifiedAtMs,
        };
        // When it is passed to open
        const error = await failure(
            client.open(
                { op: "enroll" },
                forged as unknown as Parameters<ChannelClient["open"]>[1],
            ),
        );
        // Then the runtime brand check refuses it (B-13)
        expectChannelError(error, "UNVERIFIED_BUNDLE");
    });
});

describe("SR-1 / D-043 pinned jwks_uri over live HTTP", () => {
    it("fetches only the pinned jwks_uri while opening a session (N1)", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const { session } = await connect(h, parts);
        await session.close();
        expect(parts.fetcher.urls.length).toBeGreaterThan(0);
        expect(new Set(parts.fetcher.urls)).toEqual(new Set([h.jwksUri]));
        expect(parts.fetcher.urls.some((u) => u.includes("openid-configuration"))).toBe(false);
    });

    it("rejects a token signed by a key at another path on the issuer origin (N2)", async () => {
        const h = await harness.get();
        const fetcher = new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 10_000 });
        // Given the attacker's JWKS is reachable on the same origin
        expect((await fetcher.get(h.fixture.attacker_jwks_url)).status).toBe(200);
        // When the attacker's token is verified against the pinned profile
        const error = await failure(
            verifyAttestation(
                h.fixture.attacker_token,
                h.profile,
                { identityNonce: new Uint8Array(32) },
                { report: () => Promise.resolve() },
                {
                    crypto: createWebCrypto(),
                    fetcher,
                    now: () => Date.now(),
                    limits: DEFAULT_CHANNEL_LIMITS.verifier,
                },
            ),
        );
        // Then the signature check fails closed
        expect(error).toBeInstanceOf(AttestationError);
        expect((error as AttestationError).check).toBe("signature");
        expect((error as AttestationError).code).toBe("UNTRUSTED_SIGNER");
    });
});

describe("FR-5 response routing", () => {
    it("delivers a session's responses on its client route and nothing on another route", async () => {
        const h = await harness.get();
        const parts = clientParts(h);
        const { session } = await connect(h, parts);
        await session.request("test.echo", echo(1));
        await session.close();
        // When a stranger polls a route that never opened a session
        const transport = parts.config.transport;
        const stranger = await transport.getResponses("ee".repeat(16));
        // Then it sees nothing, and the fixture client's route holds ciphertext only
        expect(stranger.responses).toHaveLength(0);
        const own = await transport.getResponses(h.fixture.client_id);
        expect(own.responses.length).toBeGreaterThan(0);
        const cs = h.fixture.cs;
        for (const r of own.responses) {
            expect(bytesToHex(r.body)).not.toContain(cs);
        }
    });
});
