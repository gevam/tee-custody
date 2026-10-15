// Shared helpers for INC-2 acceptance tests (QA): the live end-to-end harness (TL-8, INC-2-API 9.4)
// and a few independent test doubles. Synthetic values only; public interfaces only.
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    AttestationError,
    BundleError,
    ChannelError,
    DEFAULT_CHANNEL_LIMITS,
    decodeCanonical,
    encodeCanonical,
    parseTrustProfile,
    verifyAttestation,
    verifyBundle,
    type Bytes,
    type CanonicalValue,
    type ChannelClientConfig,
    type ChannelLimits,
    type Crypto,
    type DecodeLimits,
    type FetchResponse,
    type Fetcher,
    type PublishedBundle,
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
    // Never orphan the harness (ports, the tc-e2e-* dir with the fixture share) if this runner dies:
    // 'exit' covers a normal or SIGTERM-driven worker exit; SIGINT/SIGTERM are forwarded then re-raised.
    const killChild = (): void => {
        if (child.exitCode === null && child.signalCode === null) {
            child.kill("SIGTERM");
        }
    };
    process.once("exit", killChild);
    for (const sig of ["SIGINT", "SIGTERM"] as const) {
        process.once(sig, () => {
            killChild();
            process.kill(process.pid, sig);
        });
    }
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
    pollIntervalMs: DEFAULT_CHANNEL_LIMITS.pollIntervalMs,
});

/**
 * Stand-in for the persistent used-pre-key set of a host with one client (D-01 F4). Each test builds a
 * fresh ChannelClient, whose own used set is empty; a pre-key consumed by an earlier test stays listed
 * for up to bundle_republish_min_interval_s (INC-2-API 4.13), and picking it gives no response.
 */
const consumedPrekeys = new Map<string, Set<number>>();

function recordOpen(instance: string, body: Uint8Array): void {
    try {
        const env = decodeCanonical(body, DEFAULT_CHANNEL_LIMITS.bundle.decode);
        if (!(env instanceof Map) || env.get("kind") !== "open") {
            return;
        }
        const aad = decodeCanonical(
            env.get("aad") as Uint8Array,
            DEFAULT_CHANNEL_LIMITS.bundle.decode,
        );
        const id = Number((aad as Map<string, CanonicalValue>).get("prekey_id"));
        const set = consumedPrekeys.get(instance) ?? new Set<number>();
        set.add(id);
        consumedPrekeys.set(instance, set);
    } catch {
        // not an open envelope we can read: nothing to record
    }
}

function withLedger(inner: Transport): Transport {
    return {
        getResponses: (client, after) => inner.getResponses(client, after),
        postRequest: (instance, body) => {
            recordOpen(instance, body);
            return inner.postRequest(instance, body);
        },
        listBundles: async (): Promise<readonly PublishedBundle[]> => {
            const real = await inner.listBundles();
            const out: PublishedBundle[] = [];
            for (const p of real) {
                const used = consumedPrekeys.get(p.instanceId);
                if (used === undefined || used.size === 0) {
                    out.push(p);
                    continue;
                }
                const map = new Map(
                    decodeCanonical(p.bundle, DEFAULT_CHANNEL_LIMITS.bundle.decode) as Map<
                        string,
                        CanonicalValue
                    >,
                );
                const keys = (map.get("prekeys") as CanonicalValue[]).filter(
                    (entry) => !used.has(Number((entry as Map<string, CanonicalValue>).get("id"))),
                );
                if (keys.length === 0) {
                    continue; // every listed pre-key is consumed; wait for the republish
                }
                map.set("prekeys", keys);
                out.push({ instanceId: p.instanceId, bundle: encodeCanonical(map) });
            }
            return out;
        },
    };
}

function code(error: unknown): string {
    if (error instanceof BundleError) {
        return `BundleError:${error.code}`;
    }
    if (error instanceof AttestationError) {
        return `AttestationError:${error.check}/${error.code}`;
    }
    if (error instanceof ChannelError) {
        return `ChannelError:${error.code}`;
    }
    return error instanceof Error ? error.name : "non-error";
}

/** Seconds from now to the token's nbf/iat/exp claims (numbers only; no token content is printed). */
function claimTiming(p: PublishedBundle, decode: DecodeLimits): string {
    try {
        const m = decodeCanonical(p.bundle, decode) as Map<string, CanonicalValue>;
        const payload = (m.get("token") as string).split(".")[1] ?? "";
        const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<
            string,
            unknown
        >;
        const now = Date.now() / 1000;
        const delta = (k: string): string =>
            typeof claims[k] === "number" ? (claims[k] - now).toFixed(3) : "absent";
        return `claimDeltaSec(nbf=${delta("nbf")} iat=${delta("iat")} exp=${delta("exp")})`;
    } catch {
        return "claimDeltaSec(unreadable)";
    }
}

/** Codes only (never tokens, keys or payloads): per listed bundle, what verifyBundle/verifyAttestation say. */
export async function diagnoseBundles(h: Harness, parts: TestClientParts): Promise<string> {
    const crypto = createWebCrypto();
    const fetcher = new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 10_000 });
    const limits = parts.config.limits ?? DEFAULT_CHANNEL_LIMITS;
    const sink = { report: () => Promise.resolve() };
    let listed: readonly PublishedBundle[];
    try {
        listed = await parts.config.transport.listBundles();
    } catch (error) {
        return `listBundles failed: ${code(error)}`;
    }
    const lines: string[] = [`${String(listed.length)} bundle(s) listed`];
    for (const [n, p] of listed.entries()) {
        let verifyBundleResult = "ok";
        try {
            await verifyBundle(p, h.profile, sink, {
                crypto,
                fetcher,
                now: () => Date.now(),
                verifierLimits: limits.verifier,
                bundleLimits: limits.bundle,
            });
        } catch (error) {
            verifyBundleResult = code(error);
        }
        let attestResult = "ok";
        try {
            const m = decodeCanonical(p.bundle, limits.bundle.decode) as Map<
                string,
                CanonicalValue
            >;
            const nonce = await crypto.sha256((m.get("IK_pub") as Uint8Array).slice());
            await verifyAttestation(
                m.get("token") as string,
                h.profile,
                { identityNonce: nonce },
                sink,
                { crypto, fetcher, now: () => Date.now(), limits: limits.verifier },
            );
        } catch (error) {
            attestResult = code(error);
        }
        const timing = attestResult === "ok" ? "" : ` ${claimTiming(p, limits.bundle.decode)}`;
        lines.push(
            `bundle[${String(n)}] verifyBundle=${verifyBundleResult} verifyAttestation=${attestResult}${timing}`,
        );
    }
    return lines.join("; ");
}

/** Awaits `work`; a NO_VERIFIED_BUNDLE rejection is rethrown with per-bundle diagnostic codes (D-01 item 5). */
export async function withBundleDiagnostics<T>(
    h: Harness,
    parts: TestClientParts,
    work: Promise<T>,
): Promise<T> {
    try {
        return await work;
    } catch (error) {
        if (error instanceof ChannelError && error.code === "NO_VERIFIED_BUNDLE") {
            const detail = await diagnoseBundles(h, parts);
            throw new Error(`NO_VERIFIED_BUNDLE unexpected: ${detail}`, { cause: error });
        }
        throw error;
    }
}

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
    const ledgered = withLedger(base);
    const transport = options.transport ? options.transport(ledgered) : ledgered;
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
