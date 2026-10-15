// T-31: the Node client, composed from the real web adapters, against the live end-to-end harness
// (INC-2-API §9.4, §16.9 N1–N3; API-TL TL-8, TL-10; FR-4, FR-5, SR-1). The harness runs with a bounded
// start-up wait and is stopped (SIGTERM, then SIGKILL) after the file, so a hung harness fails here.
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
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
import { afterAll, beforeAll, describe, expect, it, onTestFinished, vi } from "vitest";

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

interface SpawnOptions {
    readonly readyLine?: RegExp;
    readonly readyTimeoutMs?: number;
    readonly env?: NodeJS.ProcessEnv;
}

interface Spawned {
    readonly proc: ChildProcess;
    readonly ready: Promise<Harness>;
}

let child: ChildProcess | undefined;
let harness: Harness | undefined;

function readHarness(match: RegExpExecArray): Harness {
    const profilePath = match[3] ?? "";
    const profileJson = JSON.parse(readFileSync(profilePath, "utf8")) as { jwks_uri: string };
    return {
        gateway: match[1] ?? "",
        profilePath,
        profileJson,
        profile: parseTrustProfile(profileJson),
        fixture: JSON.parse(
            readFileSync(join(dirname(profilePath), "fixture.json"), "utf8"),
        ) as Fixture,
    };
}

function spawnHarness(options: SpawnOptions = {}): Spawned {
    const readyLine = options.readyLine ?? READY_LINE;
    // stdin is a pipe Node never writes to: if this worker dies by any means, the kernel closes it and
    // the harness (--stop-on-stdin-eof) stops itself and removes FIXTURE_CS (T-31 A6).
    const proc = spawn(
        "uv",
        ["run", "python", "tests/e2e/channel_harness.py", "--stop-on-stdin-eof"],
        {
            cwd: REPO_ROOT,
            env: options.env ?? process.env,
            stdio: ["pipe", "pipe", "ignore"],
            detached: true, // its own process group: uv and the harness are signalled together
        },
    );
    const ready = new Promise<Harness>((resolveReady, reject) => {
        let out = "";
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            // Rejected only once the whole group has stopped, so nothing outlives the timeout.
            void stopProcess(proc).then(() => {
                reject(new Error("HARNESS_TIMEOUT"));
            });
        }, options.readyTimeoutMs ?? READY_TIMEOUT_MS);
        proc.stdout.on("data", (chunk: Buffer) => {
            out += chunk.toString();
            const match = readyLine.exec(out);
            if (match) {
                clearTimeout(timer);
                resolveReady(readHarness(match));
            }
        });
        proc.on("exit", (code) => {
            clearTimeout(timer);
            if (!timedOut) {
                reject(new Error(`HARNESS_EXITED:${String(code)}`));
            }
        });
    });
    return { proc, ready };
}

function startHarness(): Promise<Harness> {
    const spawned = spawnHarness();
    child = spawned.proc;
    return spawned.ready;
}

function signalGroup(proc: ChildProcess, signal: NodeJS.Signals | 0): boolean {
    if (proc.pid === undefined) {
        return false;
    }
    try {
        process.kill(-proc.pid, signal);
        return true;
    } catch {
        return false; // ESRCH: no process is left in the group
    }
}

// SIGTERM to the whole group (the harness cleans up); SIGKILL to the group after timeoutMs,
// or at once if anything in the group outlives uv.
function stopProcess(proc: ChildProcess, timeoutMs = STOP_TIMEOUT_MS): Promise<void> {
    return new Promise<void>((done) => {
        const finish = (): void => {
            clearTimeout(timer);
            if (signalGroup(proc, 0)) {
                signalGroup(proc, "SIGKILL");
            }
            done();
        };
        const timer = setTimeout(() => signalGroup(proc, "SIGKILL"), timeoutMs);
        if (proc.exitCode !== null || proc.signalCode !== null) {
            finish();
            return;
        }
        proc.once("exit", finish);
        signalGroup(proc, "SIGTERM");
    });
}

function stopHarness(): Promise<void> {
    return child === undefined ? Promise.resolve() : stopProcess(child);
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

interface Client {
    readonly channel: ChannelClient;
    readonly config: ChannelClientConfig;
    readonly transport: FetchTransport;
    readonly fetcher: RecordingFetcher;
    readonly sink: RecordingSink;
}

let shared: Client | undefined;

// One client for the whole file: its used-pre-key set then covers every open made here, so no open
// can pick a pre-key an earlier open consumed while the workload's bundle still lists it.
function client(h: Harness): Client {
    shared ??= compose(h);
    return shared;
}

function compose(h: Harness): Client {
    const transport = new FetchTransport({
        baseUrl: h.gateway,
        timeoutMs: 10_000,
    });
    const fetcher = new RecordingFetcher(fetchFetcher());
    const sink = new RecordingSink();
    const config: ChannelClientConfig = {
        trustProfile: h.profile,
        transport,
        crypto: createWebCrypto(),
        fetcher,
        securityEvents: sink,
        clock: systemClock,
    };
    return { channel: new ChannelClient(config), config, transport, fetcher, sink };
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
        const parts = client(h);
        const { session } = await parts.channel.open(openSession(h));
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
        const error = await rejection(client(h).channel.open(openSession(h, wrong)));
        expect(error).toBeInstanceOf(ChannelError);
        expect((error as ChannelError).code).toBe("REMOTE_ERROR");
        expect((error as ChannelError).detail).toBe("AUTHENTICATION_FAILED");
    });
});

describe("FR-5 response routing", () => {
    it("delivers responses only on the AAD route; another route gets an empty page (criterion 6)", async () => {
        const h = live();
        const parts = client(h);
        const { session } = await parts.channel.open(openSession(h));
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
        const parts = client(h);
        const { session } = await parts.channel.open(openSession(h));
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

function exitWithin(proc: ChildProcess, ms: number): Promise<void> {
    return new Promise<void>((done) => {
        if (proc.exitCode !== null || proc.signalCode !== null) {
            done();
            return;
        }
        const timer = setTimeout(done, ms);
        proc.once("exit", () => {
            clearTimeout(timer);
            done();
        });
    });
}

describe("harness lifecycle", () => {
    it("stops and cleans up on stdin EOF alone, with no signal (criterion 12)", async () => {
        const spawned = spawnHarness();
        try {
            const h = await spawned.ready;
            // When the spawner's end of the stdin pipe closes (as when the vitest worker dies)
            spawned.proc.stdin?.end();
            // Then the harness exits 0, its whole group is gone, and its temp dir is removed
            await exitWithin(spawned.proc, STOP_TIMEOUT_MS);
            expect(spawned.proc.exitCode).toBe(0);
            expect(signalGroup(spawned.proc, 0)).toBe(false);
            expect(existsSync(dirname(h.profilePath))).toBe(false);
        } finally {
            await stopProcess(spawned.proc);
        }
    });

    // Every process whose environment carries TMPDIR=<dir>: uv and the harness it started.
    function processesWithTmpdir(dir: string): number[] {
        const marker = `\0TMPDIR=${dir}\0`;
        return readdirSync("/proc")
            .filter((name) => /^\d+$/.test(name))
            .filter((pid) => {
                try {
                    return `\0${readFileSync(`/proc/${pid}/environ`, "latin1")}`.includes(marker);
                } catch {
                    return false;
                }
            })
            .map(Number);
    }

    it("leaves no harness process and no tc-e2e-* dir after a forced ready timeout", async () => {
        const dir = mkdtempSync(join(tmpdir(), "tc-t31-"));
        try {
            // Given a harness that comes up fully but whose ready line is never recognised
            const spawned = spawnHarness({
                readyLine: /^never$/,
                readyTimeoutMs: 5_000,
                env: { ...process.env, TMPDIR: dir },
            });
            // When the ready wait times out
            await expect(spawned.ready).rejects.toThrow("HARNESS_TIMEOUT");
            // Then the whole process tree is gone and the harness removed its temp dir
            expect(processesWithTmpdir(dir)).toEqual([]);
            expect(readdirSync(dir).filter((name) => name.startsWith("tc-e2e-"))).toEqual([]);
        } finally {
            rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe("stopProcess group fallback (C2)", () => {
    const IGNORES_SIGTERM =
        'process.on("SIGTERM",()=>{});console.log("ready");setInterval(()=>{},1e3)';

    function readyOn(proc: ChildProcess): Promise<void> {
        return new Promise<void>((resolveReady, reject) => {
            const timer = setTimeout(() => {
                reject(new Error("NOT_READY"));
            }, 10_000);
            let out = "";
            proc.stdout?.on("data", (chunk: Buffer) => {
                out += chunk.toString();
                if (out.includes("ready")) {
                    clearTimeout(timer);
                    resolveReady();
                }
            });
        });
    }

    async function groupGoneWithin(proc: ChildProcess, ms: number): Promise<boolean> {
        const deadline = Date.now() + ms;
        while (signalGroup(proc, 0)) {
            if (Date.now() >= deadline) {
                return false;
            }
            await new Promise((r) => setTimeout(r, 50));
        }
        return true;
    }

    it("SIGKILLs the group once timeoutMs passes when SIGTERM is ignored (13a)", async () => {
        const proc = spawn(process.execPath, ["-e", IGNORES_SIGTERM], {
            detached: true,
            stdio: ["ignore", "pipe", "ignore"],
        });
        onTestFinished(() => {
            signalGroup(proc, "SIGKILL"); // also runs when the test times out
        });
        try {
            await readyOn(proc);
            const started = Date.now();
            await stopProcess(proc, 500);
            expect(Date.now() - started).toBeGreaterThanOrEqual(400);
            expect(proc.signalCode).toBe("SIGKILL");
            expect(signalGroup(proc, 0)).toBe(false);
        } finally {
            signalGroup(proc, "SIGKILL");
        }
    }, 15_000);

    it("SIGKILLs a group member that outlives the leader, without waiting for the timer (13b)", async () => {
        const leader = `require("node:child_process").spawn(process.execPath, ["-e", ${JSON.stringify(
            IGNORES_SIGTERM,
        )}], { stdio: ["ignore", "inherit", "ignore"] }); setInterval(() => {}, 1e3);`;
        const proc = spawn(process.execPath, ["-e", leader], {
            detached: true,
            stdio: ["ignore", "pipe", "ignore"],
        });
        onTestFinished(() => {
            signalGroup(proc, "SIGKILL"); // also runs when the test times out
        });
        try {
            await readyOn(proc);
            const started = Date.now();
            await stopProcess(proc, 60_000);
            expect(Date.now() - started).toBeLessThan(5_000);
            expect(await groupGoneWithin(proc, 2_000)).toBe(true);
        } finally {
            signalGroup(proc, "SIGKILL");
        }
    }, 15_000);
});
