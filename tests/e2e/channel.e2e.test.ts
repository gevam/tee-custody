// T-31: the Node client, composed from the real web adapters, against the live end-to-end harness
// (INC-2-API §9.4, §16.9 N1–N3; API-TL TL-8, TL-10; FR-4, FR-5, SR-1). The harness runs with a bounded
// start-up wait and is stopped (SIGTERM, then SIGKILL) after the file, so a hung harness fails here.
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
    AttestationError,
    ChannelClient,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    parseTrustProfile,
    verifyAttestation,
    type CanonicalValue,
    type ChannelClientConfig,
    type FetchResponse,
    type Fetcher,
    type SecurityEvent,
    type SecurityEventSink,
    type TrustProfile,
} from "@teecustody/core";
import { FetchFetcher, FetchTransport, createWebCrypto, systemClock } from "@teecustody/web";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.setConfig({ testTimeout: 60_000, hookTimeout: 60_000 });

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const READY_LINE =
    /^gateway=(http:\/\/127\.0\.0\.1:\d+) issuer=(http:\/\/127\.0\.0\.1:\d+) profile=(\/\S+)$/m;
const READY_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 10_000;
const CLI = join(REPO_ROOT, "packages/teecustody-web/dist/profile/bin.js");
const run = promisify(execFile);

interface Fixture {
    readonly client_id: string;
    readonly cs: string;
    readonly key_id: string;
    readonly epoch: number;
    readonly discovery_url: string;
    readonly attacker_jwks_url: string;
    readonly attacker_token: string;
}

interface Harness {
    readonly gateway: string;
    readonly profilePath: string;
    readonly profileJson: { readonly jwks_uri: string };
    readonly profile: TrustProfile;
    readonly fixture: Fixture;
}

let child: ChildProcess | undefined;
let harness: Harness | undefined;

function startHarness(): Promise<Harness> {
    const proc = spawn("uv", ["run", "python", "tests/e2e/channel_harness.py"], {
        cwd: REPO_ROOT,
        stdio: ["ignore", "pipe", "ignore"],
    });
    child = proc;
    return new Promise<Harness>((resolveReady, reject) => {
        let out = "";
        const timer = setTimeout(() => {
            proc.kill("SIGKILL");
            reject(new Error("HARNESS_TIMEOUT"));
        }, READY_TIMEOUT_MS);
        proc.stdout.on("data", (chunk: Buffer) => {
            out += chunk.toString();
            const match = READY_LINE.exec(out);
            if (match) {
                clearTimeout(timer);
                const profilePath = match[3] ?? "";
                const profileJson = JSON.parse(readFileSync(profilePath, "utf8")) as {
                    jwks_uri: string;
                };
                resolveReady({
                    gateway: match[1] ?? "",
                    profilePath,
                    profileJson,
                    profile: parseTrustProfile(profileJson),
                    fixture: JSON.parse(
                        readFileSync(join(dirname(profilePath), "fixture.json"), "utf8"),
                    ) as Fixture,
                });
            }
        });
        proc.on("exit", (code) => {
            clearTimeout(timer);
            reject(new Error(`HARNESS_EXITED:${String(code)}`));
        });
    });
}

function stopHarness(): Promise<void> {
    const proc = child;
    if (proc === undefined || proc.exitCode !== null || proc.signalCode !== null) {
        return Promise.resolve();
    }
    return new Promise<void>((done) => {
        const timer = setTimeout(() => proc.kill("SIGKILL"), STOP_TIMEOUT_MS);
        proc.once("exit", () => {
            clearTimeout(timer);
            done();
        });
        proc.kill("SIGTERM");
    });
}

beforeAll(async () => {
    harness = await startHarness();
});

afterAll(async () => {
    await stopHarness();
});

function live(): Harness {
    if (harness === undefined) {
        throw new Error("HARNESS_NOT_STARTED");
    }
    return harness;
}

class RecordingSink implements SecurityEventSink {
    readonly events: SecurityEvent[] = [];
    report(event: SecurityEvent): Promise<void> {
        this.events.push(event);
        return Promise.resolve();
    }
}

class RecordingFetcher implements Fetcher {
    readonly urls: string[] = [];
    constructor(private readonly inner: Fetcher) {}
    get(url: string): Promise<FetchResponse> {
        this.urls.push(url);
        return this.inner.get(url);
    }
}

function fetchFetcher(): FetchFetcher {
    return new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 10_000 });
}

function compose(h: Harness): {
    config: ChannelClientConfig;
    transport: FetchTransport;
    fetcher: RecordingFetcher;
    sink: RecordingSink;
} {
    const transport = new FetchTransport({
        baseUrl: h.gateway,
        maxResponseBytes: 1_048_576,
        timeoutMs: 10_000,
    });
    const fetcher = new RecordingFetcher(fetchFetcher());
    const sink = new RecordingSink();
    return {
        config: {
            trustProfile: h.profile,
            transport,
            crypto: createWebCrypto(),
            fetcher,
            securityEvents: sink,
            clock: systemClock,
        },
        transport,
        fetcher,
        sink,
    };
}

function hex(text: string): Uint8Array {
    return new Uint8Array(Buffer.from(text, "hex"));
}

function openSession(h: Harness, cs: Uint8Array = hex(h.fixture.cs)) {
    return {
        op: "open_session" as const,
        clientId: h.fixture.client_id,
        cs,
        keyId: hex(h.fixture.key_id),
        epoch: h.fixture.epoch,
    };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

describe("FR-4 channel over the live harness", () => {
    it("opens a session, echoes a request and closes, with no security event (criterion 4)", async () => {
        const h = live();
        const parts = compose(h);
        const { session } = await new ChannelClient(parts.config).open(openSession(h));
        const input = new Map<string, CanonicalValue>([["x", 1]]);
        const echoed = await session.request("test.echo", input);
        await session.close();
        expect(echoed).toEqual(input);
        expect(parts.sink.events).toEqual([]);
        expect(session.closed).toBe(true);
    });

    it("refuses a wrong client share with an authenticated remote error (criterion 5)", async () => {
        const h = live();
        const wrong = hex(h.fixture.cs).map((byte) => byte ^ 0xff);
        const error = await rejection(
            new ChannelClient(compose(h).config).open(openSession(h, wrong)),
        );
        expect(error).toBeInstanceOf(ChannelError);
        expect((error as ChannelError).code).toBe("REMOTE_ERROR");
        expect((error as ChannelError).detail).toBe("AUTHENTICATION_FAILED");
    });
});

describe("FR-5 response routing", () => {
    it("delivers responses only on the AAD route; another route gets an empty page (criterion 6)", async () => {
        const h = live();
        const parts = compose(h);
        const { session } = await new ChannelClient(parts.config).open(openSession(h));
        await session.request("test.echo", new Map<string, CanonicalValue>([["x", 2]]));
        await session.close();
        const other = h.fixture.client_id === "f".repeat(32) ? "e".repeat(32) : "f".repeat(32);
        const stranger = await parts.transport.getResponses(other);
        expect(stranger.responses).toEqual([]);
        const own = await parts.transport.getResponses(h.fixture.client_id);
        expect(own.responses.length).toBeGreaterThan(0);
    });
});

describe("SR-1 / D-043 pinned jwks_uri over live HTTP", () => {
    it("fetches only profile.jwks_uri during ChannelClient.open (N1, criterion 8)", async () => {
        const h = live();
        const parts = compose(h);
        const { session } = await new ChannelClient(parts.config).open(openSession(h));
        await session.close();
        expect(parts.fetcher.urls.length).toBeGreaterThan(0);
        for (const url of parts.fetcher.urls) {
            expect(url).toBe(h.profileJson.jwks_uri);
        }
    });

    it("rejects the attacker token at signature while its JWKS is served (N2, criterion 9)", async () => {
        const h = live();
        const fetcher = fetchFetcher();
        expect((await fetcher.get(h.fixture.attacker_jwks_url)).status).toBe(200);
        const error = await rejection(
            verifyAttestation(
                h.fixture.attacker_token,
                h.profile,
                { identityNonce: new Uint8Array(32) },
                new RecordingSink(),
                {
                    crypto: createWebCrypto(),
                    fetcher,
                    now: () => Date.now(),
                    limits: DEFAULT_CHANNEL_LIMITS.verifier,
                },
            ),
        );
        expect(error).toBeInstanceOf(AttestationError);
        expect((error as AttestationError).check).toBe("signature");
        expect((error as AttestationError).code).toBe("UNTRUSTED_SIGNER");
    });

    it("check-discovery binds the harness profile and reports the echoed JWKS origin (N3, criterion 10)", async () => {
        const h = live();
        await run("pnpm", ["--filter", "@teecustody/web", "run", "build:cli"], {
            cwd: REPO_ROOT,
            timeout: 50_000,
        });
        const env = { ...process.env };
        delete env.NODE_TLS_REJECT_UNAUTHORIZED;
        const { stdout } = await run(
            "node",
            [
                CLI,
                "check-discovery",
                "--profile",
                h.profilePath,
                "--discovery-url",
                h.fixture.discovery_url,
                "--probe-cors",
                "http://127.0.0.1:1",
            ],
            { cwd: REPO_ROOT, env, timeout: 30_000 },
        );
        const lines = stdout.split("\n").filter((line) => line !== "");
        expect(lines).toHaveLength(1);
        expect(lines[0]).toMatch(/ jwks_acao=http:\/\/127\.0\.0\.1:1 discovery_acao=absent$/);
    });
});
