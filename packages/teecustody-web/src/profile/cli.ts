// `teecustody-profile check-discovery` (INC-2-API §16.5 CLI; API-TL TL-10; D-043, ADR 0012 rule 3; SR-1, SR-11).
// Node >= 22 only. Never imported by src/index.ts, so it is outside the browser bundle and the SR-13 scan entry.
// There is no skip, offline or allow-mismatch option (I13). Output is one line: the success line or a code.
import { closeSync, openSync, readSync } from "node:fs";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";

import { parseTrustProfile, utf8DecodeStrict, type TrustProfile } from "@teecustody/core";

import { FetchFetcher } from "../fetch/fetcher.js";
import {
    DiscoveryBindingError,
    GOOGLE_DISCOVERY_URL,
    checkDiscoveryBinding,
    type DiscoveryBindingReport,
} from "./discovery-binding.js";

export interface CliIo {
    readonly stdout: (line: string) => void;
    readonly stderr: (line: string) => void;
}

const MAX_BYTES = 65536;
const DEFAULT_TIMEOUT_MS = 10000;
const MAX_TIMEOUT_MS = 60000;
const OPTIONS: ReadonlySet<string> = new Set([
    "--profile",
    "--discovery-url",
    "--probe-cors",
    "--timeout-ms",
]);
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "localhost", "[::1]"]);
const PRINTABLE_HEADER = /^[!-~]{1,256}$/;

class CliFailure extends Error {
    constructor(
        readonly code: string,
        readonly exitCode: number,
    ) {
        super(code);
    }
}

const invalidArgument = (): CliFailure => new CliFailure("INVALID_ARGUMENT", 2);

// Every option takes exactly one value; an unknown, repeated or valueless option is refused.
function parseOptions(args: readonly string[]): ReadonlyMap<string, string> {
    const options = new Map<string, string>();
    for (const [index, name] of args.entries()) {
        if (index % 2 === 1) {
            continue;
        }
        const value = args[index + 1];
        if (!OPTIONS.has(name) || options.has(name) || value === undefined) {
            throw invalidArgument();
        }
        options.set(name, value);
    }
    return options;
}

function parseTimeout(value: string | undefined): number {
    if (value === undefined) {
        return DEFAULT_TIMEOUT_MS;
    }
    if (!/^[1-9][0-9]*$/.test(value) || Number(value) > MAX_TIMEOUT_MS) {
        throw invalidArgument();
    }
    return Number(value);
}

// Reads at most MAX_BYTES; a file with one byte more is refused, never truncated.
function readBounded(path: string): Uint8Array {
    const buffer = new Uint8Array(MAX_BYTES + 1);
    const fd = openSync(path, "r");
    try {
        let length = 0;
        let read = -1;
        while (read !== 0 && length < buffer.byteLength) {
            read = readSync(fd, buffer, length, buffer.byteLength - length, null);
            length += read;
        }
        if (length > MAX_BYTES) {
            throw new RangeError("oversize");
        }
        return buffer.subarray(0, length);
    } finally {
        closeSync(fd);
    }
}

function readProfile(path: string): TrustProfile {
    try {
        return parseTrustProfile(JSON.parse(utf8DecodeStrict(readBounded(path))));
    } catch {
        throw new CliFailure("INVALID_PROFILE", 2);
    }
}

function resolveDiscoveryUrl(profile: TrustProfile, given: string | undefined): string {
    if (profile.profile_kind === "production") {
        if (given !== undefined && given !== GOOGLE_DISCOVERY_URL) {
            throw invalidArgument();
        }
        return GOOGLE_DISCOVERY_URL;
    }
    if (given === undefined) {
        throw invalidArgument();
    }
    return given;
}

function checkProbeOrigin(origin: string): void {
    let url: URL;
    try {
        url = new URL(origin);
    } catch {
        throw invalidArgument();
    }
    const allowed =
        url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
    if (url.origin !== origin || !allowed) {
        throw invalidArgument();
    }
}

async function bind(
    profile: TrustProfile,
    discoveryUrl: string,
    timeoutMs: number,
): Promise<DiscoveryBindingReport> {
    try {
        return await checkDiscoveryBinding(
            { profile, discoveryUrl },
            {
                fetcher: new FetchFetcher({ maxBodyBytes: MAX_BYTES, timeoutMs }),
                maxDocumentBytes: MAX_BYTES,
            },
        );
    } catch (error) {
        // A3 R1: only a DiscoveryBindingError carries a code; anything else is a defect and propagates.
        if (error instanceof DiscoveryBindingError) {
            throw new CliFailure(error.code, error.code === "INVALID_ARGUMENT" ? 2 : 1);
        }
        throw error;
    }
}

interface ProbeResult {
    readonly status: number | undefined;
    readonly acao: string | undefined;
}

// One GET carrying only the Origin header (plus the mandatory Host): no redirect, credentials, cookies or proxy.
// The body is discarded after at most MAX_BYTES. Resolves null on a transport failure, a truncated body or the
// deadline.
function issueProbe(url: string, origin: string, timeoutMs: number): Promise<ProbeResult | null> {
    const send = url.startsWith("https:") ? httpsRequest : httpRequest;
    return new Promise((resolve) => {
        const request = send(url, { method: "GET", headers: { Origin: origin }, agent: false });
        request.removeHeader("Connection");
        const settle = (result: ProbeResult | null): void => {
            clearTimeout(timer);
            request.destroy();
            resolve(result);
        };
        const timer = setTimeout(() => {
            settle(null);
        }, timeoutMs);
        request.on("error", () => {
            settle(null);
        });
        request.on("response", (response: IncomingMessage) => {
            const result = {
                status: response.statusCode,
                acao: response.headers["access-control-allow-origin"],
            };
            let received = 0;
            response.on("data", (chunk: Uint8Array) => {
                received += chunk.byteLength;
                if (received > MAX_BYTES) {
                    settle(result);
                }
            });
            // A body cut short (no `end`) is a failed probe, not a pass on the headers alone.
            response.on("close", () => {
                settle(response.complete ? result : null);
            });
        });
        request.end();
    });
}

// A3 R1: any throw while a probe is issued (a synchronous throw from `request` rejects the executor's promise) is
// a probe transport failure.
async function probe(url: string, origin: string, timeoutMs: number): Promise<ProbeResult | null> {
    try {
        return await issueProbe(url, origin, timeoutMs);
    } catch {
        return null;
    }
}

function shown(acao: string | undefined): string {
    if (acao === undefined) {
        return "absent";
    }
    return PRINTABLE_HEADER.test(acao) ? acao : "invalid";
}

async function probeCors(
    profile: TrustProfile,
    discoveryUrl: string,
    origin: string,
    timeoutMs: number,
): Promise<string> {
    const jwks = await probe(profile.jwks_uri, origin, timeoutMs);
    if (jwks?.status !== 200 || (jwks.acao !== "*" && jwks.acao !== origin)) {
        throw new CliFailure("CORS_MISSING", 1);
    }
    // Informational only: D-043's revisit trigger is a value other than `absent`.
    const discovery = await probe(discoveryUrl, origin, timeoutMs);
    return ` jwks_acao=${shown(jwks.acao)} discovery_acao=${shown(discovery?.acao)}`;
}

async function checkDiscovery(args: readonly string[]): Promise<string> {
    const options = parseOptions(args);
    const profilePath = options.get("--profile");
    if (profilePath === undefined) {
        throw invalidArgument();
    }
    const timeoutMs = parseTimeout(options.get("--timeout-ms"));
    const profile = readProfile(profilePath);
    const discoveryUrl = resolveDiscoveryUrl(profile, options.get("--discovery-url"));
    const origin = options.get("--probe-cors");
    if (origin !== undefined) {
        checkProbeOrigin(origin);
    }
    const report = await bind(profile, discoveryUrl, timeoutMs);
    const keys = String(report.usableKeyCount);
    const line = `ok issuer=${report.issuer} jwks_uri=${report.jwksUri} keys=${keys}`;
    if (origin === undefined) {
        return line;
    }
    return line + (await probeCors(profile, discoveryUrl, origin, timeoutMs));
}

/** TL-10: `argv` excludes `node` and the script path. Returns the exit code; writes only through `io`. */
export async function main(argv: readonly string[], io: CliIo): Promise<number> {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
        io.stderr("INSECURE_TLS_ENVIRONMENT");
        return 2;
    }
    try {
        if (argv[0] !== "check-discovery") {
            throw invalidArgument();
        }
        io.stdout(await checkDiscovery(argv.slice(1)));
        return 0;
    } catch (error) {
        if (error instanceof CliFailure) {
            io.stderr(error.code);
            return error.exitCode;
        }
        // A3 R1: a defect fails closed; its message, name and stack are never written (SR-11).
        io.stderr("INTERNAL");
        return 1;
    }
}
