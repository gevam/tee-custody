// Playwright global setup for the CSP harness (INC-2-API §9.3 rev 3; API-TL TL-8; T-32).
// 1. Starts serve.mjs, so the page origin is known.
// 2. Starts the end-to-end harness with `--cors-origin <page origin> --stop-on-stdin-eof` and reads its
//    ready line.
// 3. Sends serve.mjs the gateway origin and profile path; it bundles harness.js with them and fixture.json.
// Workers receive only origins, through the environment. Both children run in their own process group
// with a stdin pipe that is never written after setup (serve.mjs: one config line). If the runner dies by
// any means the pipes close and both stop themselves; teardown stops the groups with SIGTERM, then
// SIGKILL. Every wait is bounded.
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../../../..");
const SERVE_LINE = /^serve=(http:\/\/localhost:\d+)$/m;
const SERVE_READY = /^(ready|error=[A-Z_]+)$/m;
const HARNESS_LINE =
    /^gateway=(http:\/\/127\.0\.0\.1:\d+) issuer=(http:\/\/127\.0\.0\.1:\d+) profile=(\/\S+)$/m;
const START_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 10_000;

function signalGroup(proc: ChildProcess, signal: NodeJS.Signals | 0): boolean {
    if (proc.pid === undefined) {
        return false;
    }
    try {
        process.kill(-proc.pid, signal);
        return true;
    } catch {
        return false; // ESRCH: nothing is left in the group
    }
}

// SIGTERM to the group; SIGKILL to the group after timeoutMs, or at once if anything outlives the leader.
function stopProcess(proc: ChildProcess): Promise<void> {
    return new Promise<void>((done) => {
        const timer = setTimeout(() => signalGroup(proc, "SIGKILL"), STOP_TIMEOUT_MS);
        const finish = (): void => {
            clearTimeout(timer);
            if (signalGroup(proc, 0)) {
                signalGroup(proc, "SIGKILL");
            }
            done();
        };
        if (proc.exitCode !== null || proc.signalCode !== null) {
            finish();
            return;
        }
        proc.once("exit", finish);
        signalGroup(proc, "SIGTERM");
    });
}

function start(command: string, args: readonly string[], cwd: string): ChildProcess {
    return spawn(command, args, {
        cwd,
        stdio: ["pipe", "pipe", "ignore"],
        detached: true, // its own process group
    });
}

// Resolves with the first match of `line` in the child's stdout; rejects on exit or after the timeout.
function awaitLine(proc: ChildProcess, line: RegExp, name: string): Promise<RegExpExecArray> {
    return new Promise<RegExpExecArray>((resolveLine, reject) => {
        let out = "";
        const cleanup = (): void => {
            clearTimeout(timer);
            proc.stdout?.off("data", onData);
            proc.off("exit", onExit);
        };
        const onData = (chunk: Buffer): void => {
            out += chunk.toString();
            const match = line.exec(out);
            if (match) {
                cleanup();
                resolveLine(match);
            }
        };
        const onExit = (): void => {
            cleanup();
            reject(new Error(`${name}_EXITED`));
        };
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error(`${name}_TIMEOUT`));
        }, START_TIMEOUT_MS);
        proc.stdout?.on("data", onData);
        proc.once("exit", onExit);
    });
}

export default async function globalSetup(): Promise<() => Promise<void>> {
    const children: ChildProcess[] = [];
    const teardown = async (): Promise<void> => {
        await Promise.all(children.map(stopProcess));
    };
    try {
        const serve = start(process.execPath, [resolve(HERE, "serve.mjs")], HERE);
        children.push(serve);
        const serveOrigin = (await awaitLine(serve, SERVE_LINE, "SERVE"))[1] ?? "";
        const harness = start(
            "uv",
            [
                "run",
                "python",
                "tests/e2e/channel_harness.py",
                "--cors-origin",
                serveOrigin,
                "--stop-on-stdin-eof",
            ],
            REPO_ROOT,
        );
        children.push(harness);
        const ready = await awaitLine(harness, HARNESS_LINE, "HARNESS");
        const gateway = ready[1] ?? "";
        const profilePath = ready[3] ?? "";
        serve.stdin?.write(`${JSON.stringify({ gateway, profile: profilePath })}\n`);
        const configured = (await awaitLine(serve, SERVE_READY, "SERVE"))[1];
        if (configured !== "ready") {
            throw new Error(`SERVE_${configured ?? ""}`);
        }
        const profile = JSON.parse(readFileSync(profilePath, "utf8")) as { jwks_uri: string };
        process.env.TC_SERVE_ORIGIN = serveOrigin;
        process.env.TC_GATEWAY_ORIGIN = gateway;
        process.env.TC_JWKS_ORIGIN = new URL(profile.jwks_uri).origin;
        return teardown;
    } catch (error) {
        await teardown();
        throw error;
    }
}
