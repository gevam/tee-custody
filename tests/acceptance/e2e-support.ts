// Shared helpers for INC-2 acceptance tests (QA): the live end-to-end harness (TL-8, INC-2-API 9.4)
// and a few independent test doubles. Synthetic values only; public interfaces only.
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    DEFAULT_CHANNEL_LIMITS,
    parseTrustProfile,
    type Bytes,
    type ChannelClientConfig,
    type ChannelLimits,
    type Crypto,
    type FetchResponse,
    type Fetcher,
    type SecurityEvent,
    type SecurityEventSink,
    type Transport,
    type TrustProfile,
} from "@teecustody/core";
import { FetchFetcher, FetchTransport, createWebCrypto, systemClock } from "@teecustody/web";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const HARNESS_PATH = "tests/e2e/channel_harness.py";
const READY_TIMEOUT_MS = 90_000;
const READY_LINE = /^gateway=(\S+) issuer=(\S+) profile=(\S+)$/m;

/** `fixture.json` written next to the harness profile (TL-8). Generated per run; never committed. */
export interface E2eFixture {
    readonly client_id: string;
    readonly cs: string;
    readonly key_id: string;
    readonly epoch: number;
    readonly discovery_url: string;
    readonly attacker_jwks_url: string;
    readonly attacker_token: string;
}

export interface Harness {
    readonly gateway: string;
    readonly issuer: string;
    readonly profilePath: string;
    readonly profile: TrustProfile;
    readonly jwksUri: string;
    readonly fixture: E2eFixture;
    stop(): Promise<void>;
}

export function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(Buffer.from(hex, "hex"));
}

export function bytesToHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("hex");
}

/** Starts `tests/e2e/channel_harness.py` (owned by T-31) and waits for its ready line. */
export async function startHarness(extraArgs: readonly string[] = []): Promise<Harness> {
    if (!existsSync(join(REPO_ROOT, HARNESS_PATH))) {
        throw new Error(`HARNESS_MISSING: ${HARNESS_PATH} (T-31)`);
    }
    const child: ChildProcess = spawn("uv", ["run", "python", HARNESS_PATH, ...extraArgs], {
        cwd: REPO_ROOT,
        stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    child.stderr?.on("data", (chunk: Buffer) => {
        err += chunk.toString();
    });
    const ready = await new Promise<RegExpMatchArray>((resolveReady, reject) => {
        const timer = setTimeout(() => {
            child.kill("SIGKILL");
            reject(new Error("HARNESS_TIMEOUT"));
        }, READY_TIMEOUT_MS);
        child.stdout?.on("data", (chunk: Buffer) => {
            out += chunk.toString();
            const match = READY_LINE.exec(out);
            if (match) {
                clearTimeout(timer);
                resolveReady(match);
            }
        });
        child.on("exit", (code) => {
            clearTimeout(timer);
            reject(new Error(`HARNESS_EXITED:${String(code)}:${err.slice(-300)}`));
        });
    });
    const profilePath = ready[3] ?? "";
    const fixturePath = join(dirname(profilePath), "fixture.json");
    const profileJson = JSON.parse(readFileSync(profilePath, "utf8")) as { jwks_uri: string };
    return {
        jwksUri: profileJson.jwks_uri,
        gateway: ready[1] ?? "",
        issuer: ready[2] ?? "",
        profilePath,
        profile: parseTrustProfile(profileJson),
        fixture: JSON.parse(readFileSync(fixturePath, "utf8")) as E2eFixture,
        stop: () =>
            new Promise<void>((done) => {
                if (child.exitCode !== null) {
                    done();
                    return;
                }
                child.once("exit", () => {
                    done();
                });
                child.kill("SIGTERM");
            }),
    };
}

/** A Fetcher that records every URL it is asked for, then delegates. */
export class RecordingFetcher implements Fetcher {
    readonly urls: string[] = [];
    constructor(private readonly inner: Fetcher) {}
    get(url: string): Promise<FetchResponse> {
        this.urls.push(url);
        return this.inner.get(url);
    }
}

export class EventLog implements SecurityEventSink {
    readonly events: SecurityEvent[] = [];
    report(event: SecurityEvent): Promise<void> {
        this.events.push(event);
        return Promise.resolve();
    }
}

export interface AeadCall {
    readonly keyHex: string;
    readonly nonceHex: string;
}

/** Wraps a Crypto and records (key, nonce) of every AES-GCM encryption. Independent of Core's. */
export function spyCrypto(inner: Crypto): { crypto: Crypto; calls: AeadCall[] } {
    const calls: AeadCall[] = [];
    const crypto: Crypto = {
        randomBytes: (n) => inner.randomBytes(n),
        sha256: (d) => inner.sha256(d),
        verifyEd25519: (k, d, s) => inner.verifyEd25519(k, d, s),
        verifySignature: (a, k, d, s) => inner.verifySignature(a, k, d, s),
        setupHpkeSender: (k, i) => inner.setupHpkeSender(k, i),
        setupHpkeReceiver: (k, e, i) => inner.setupHpkeReceiver(k, e, i),
        aes256GcmEncrypt: (key, nonce, aad, pt) => {
            calls.push({ keyHex: bytesToHex(key), nonceHex: bytesToHex(nonce) });
            return inner.aes256GcmEncrypt(key, nonce, aad, pt);
        },
        aes256GcmDecrypt: (k, n, a, c) => inner.aes256GcmDecrypt(k, n, a, c),
    };
    return { crypto, calls };
}

export const FAST_LIMITS: ChannelLimits = Object.freeze({
    ...DEFAULT_CHANNEL_LIMITS,
    responseTimeoutMs: 20_000,
    pollIntervalMs: 50,
});

export interface TestClientParts {
    readonly config: ChannelClientConfig;
    readonly fetcher: RecordingFetcher;
    readonly events: EventLog;
    readonly crypto: Crypto;
    readonly spyCalls: AeadCall[];
}

/** The production composition a browser host uses: web adapters over the harness gateway. */
export function clientParts(
    h: Harness,
    options: {
        transport?: (inner: Transport) => Transport;
        limits?: ChannelLimits;
    } = {},
): TestClientParts {
    const fetcher = new RecordingFetcher(
        new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 10_000 }),
    );
    const events = new EventLog();
    const spy = spyCrypto(createWebCrypto());
    const base = new FetchTransport({
        baseUrl: h.gateway,
        maxResponseBytes: 1_048_576,
        timeoutMs: 10_000,
    });
    const transport = options.transport ? options.transport(base) : base;
    return {
        config: {
            trustProfile: h.profile,
            transport,
            crypto: spy.crypto,
            fetcher,
            securityEvents: events,
            clock: systemClock,
            limits: options.limits ?? FAST_LIMITS,
        },
        fetcher,
        events,
        crypto: spy.crypto,
        spyCalls: spy.calls,
    };
}

export function concat(...parts: Bytes[]): Bytes {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
        out.set(p, at);
        at += p.length;
    }
    return out;
}

/** Lazily started, shared per test file. Failure surfaces in every test rather than as a hook error. */
export function sharedHarness(extraArgs: readonly string[] = []): {
    get(): Promise<Harness>;
    stop(): Promise<void>;
} {
    let started: Promise<Harness> | undefined;
    return {
        get(): Promise<Harness> {
            started ??= startHarness(extraArgs);
            return started;
        },
        async stop(): Promise<void> {
            if (started !== undefined) {
                const h = await started.catch(() => undefined);
                await h?.stop();
            }
        },
    };
}

/**
 * Asserts that `fn` throws an error equal (class and message) to `expected`. A stub's
 * `NOT_IMPLEMENTED: T-nn` error is rethrown unchanged so the red reason names the owning task.
 */
export function expectThrown(fn: () => unknown, expected: Error): void {
    let thrown: unknown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    if (thrown instanceof Error && thrown.message.startsWith("NOT_IMPLEMENTED")) {
        throw thrown;
    }
    if (!(thrown instanceof Error)) {
        throw new Error(`expected ${expected.name}(${expected.message}) but nothing was thrown`);
    }
    if (thrown.constructor !== expected.constructor || thrown.message !== expected.message) {
        throw new Error(
            `expected ${expected.name}(${expected.message}) but got ${thrown.name}(${thrown.message})`,
        );
    }
}
