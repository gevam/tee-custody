// `teecustody-profile check-discovery` (T-35 criterion 2; INC-2-API §16.5 CLI table, §16.9 D2; API-TL TL-10;
// SR-1, SR-11, I13). Binding runs against local node:http servers or a stubbed fetch; nothing reaches Google.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { main, type CliIo } from "../../src/profile/cli.js";

const FIXTURE_PATH = new URL("../fixtures/binding-check-production-profile.json", import.meta.url);
const FIXTURE_TEXT = readFileSync(FIXTURE_PATH, "utf8");
const PRODUCTION_JSON = JSON.parse(FIXTURE_TEXT) as Record<string, unknown>;
const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const GOOGLE_JWKS_URI =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
const GOOGLE_DISCOVERY_URL =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration";
const DISCOVERY_PATH = "/.well-known/openid-configuration";
const DEV_ISSUER = "https://issuer.binding.test";
const PROBE_ORIGIN = "http://127.0.0.1:5555";
const RSA_KEY = { kty: "RSA", kid: "k1", use: "sig", alg: "RS256", n: "AQAB", e: "AQAB" };

let dir = "";
let counter = 0;

beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "t35-cli-"));
});

afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
});

function writeFile(content: string | Uint8Array): string {
    counter += 1;
    const path = join(dir, `profile-${String(counter)}.json`);
    writeFileSync(path, content);
    return path;
}

const PRODUCTION_PATH = (): string => writeFile(FIXTURE_TEXT);

function developmentPath(jwksOrigin: string): string {
    return writeFile(
        JSON.stringify({
            ...PRODUCTION_JSON,
            profile_kind: "development",
            issuer: DEV_ISSUER,
            jwks_uri: `${jwksOrigin}/jwks`,
            allowed_hwmodels: ["TEST_HW"],
        }),
    );
}

interface Captured {
    readonly io: CliIo;
    readonly out: string[];
    readonly err: string[];
}

function capture(): Captured {
    const out: string[] = [];
    const err: string[] = [];
    return {
        io: { stdout: (line) => out.push(line), stderr: (line) => err.push(line) },
        out,
        err,
    };
}

async function cli(...argv: string[]): Promise<[number, string[], string[]]> {
    const { io, out, err } = capture();
    const code = await main(argv, io);
    return [code, out, err];
}

// ---------------------------------------------------------------------------------------------------------------
// A loopback origin. Requests without an Origin header are the binding fetches; requests with one are the probes.

interface Recorded {
    readonly method: string;
    readonly url: string;
    readonly rawHeaders: readonly string[];
}

interface OriginBehaviour {
    issuer?: string;
    discoveryJwksUri?: string;
    jwksAcao?: string | readonly string[];
    discoveryAcao?: string | readonly string[];
    jwksProbeStatus?: number;
    jwksProbe?: "hang" | "reset" | "endless" | "truncated";
    discoveryProbe?: "hang" | "reset";
}

class Origin {
    readonly recorded: Recorded[] = [];
    readonly behaviour: OriginBehaviour = {};
    readonly #server: Server;
    origin = "";

    constructor() {
        this.#server = createServer((req, res) => {
            this.#handle(req, res);
        });
    }

    async start(): Promise<this> {
        await new Promise<void>((resolve) => {
            this.#server.listen(0, "127.0.0.1", resolve);
        });
        const address = this.#server.address();
        if (address === null || typeof address === "string") {
            throw new Error("no port");
        }
        this.origin = `http://127.0.0.1:${String(address.port)}`;
        return this;
    }

    async stop(): Promise<void> {
        this.#server.closeAllConnections();
        await new Promise<void>((resolve) => {
            this.#server.close(() => {
                resolve();
            });
        });
    }

    get probes(): Recorded[] {
        return this.recorded.filter((r) => r.rawHeaders.some((h) => h.toLowerCase() === "origin"));
    }

    #handle(req: IncomingMessage, res: ServerResponse): void {
        const probe = req.headers.origin !== undefined;
        this.recorded.push({
            method: req.method ?? "",
            url: req.url ?? "",
            rawHeaders: req.rawHeaders,
        });
        const b = this.behaviour;
        if (req.url === DISCOVERY_PATH) {
            if (probe && b.discoveryProbe === "hang") {
                return;
            }
            if (probe && b.discoveryProbe === "reset") {
                req.socket.destroy();
                return;
            }
            if (probe && b.discoveryAcao !== undefined) {
                res.setHeader("Access-Control-Allow-Origin", b.discoveryAcao);
            }
            res.setHeader("Content-Type", "application/json");
            res.end(
                JSON.stringify({
                    issuer: b.issuer ?? DEV_ISSUER,
                    jwks_uri: b.discoveryJwksUri ?? `${this.origin}/jwks`,
                }),
            );
            return;
        }
        if (req.url === "/jwks") {
            if (probe && b.jwksProbe === "hang") {
                return;
            }
            if (probe && b.jwksProbe === "reset") {
                req.socket.destroy();
                return;
            }
            if (probe && b.jwksAcao !== undefined) {
                res.setHeader("Access-Control-Allow-Origin", b.jwksAcao);
            }
            if (probe && b.jwksProbeStatus !== undefined) {
                res.statusCode = b.jwksProbeStatus;
                res.setHeader("Location", "/moved");
            }
            if (probe && b.jwksProbe === "truncated") {
                res.setHeader("Content-Length", "1000");
                res.write("{");
                setTimeout(() => {
                    req.socket.destroy();
                }, 20);
                return;
            }
            if (probe && b.jwksProbe === "endless") {
                const chunk = Buffer.alloc(16384, 0x20);
                const pump = (): void => {
                    while (res.write(chunk)) {
                        // fill the socket buffer, then wait for drain
                    }
                    res.once("drain", pump);
                };
                pump();
                return;
            }
            res.end(JSON.stringify({ keys: [RSA_KEY] }));
            return;
        }
        res.statusCode = 404;
        res.end();
    }
}

async function withOrigin<T>(
    behaviour: OriginBehaviour,
    body: (origin: Origin) => Promise<T>,
): Promise<T> {
    const origin = await new Origin().start();
    Object.assign(origin.behaviour, behaviour);
    try {
        return await body(origin);
    } finally {
        await origin.stop();
    }
}

async function devRun(origin: Origin, ...extra: string[]): Promise<[number, string[], string[]]> {
    return cli(
        "check-discovery",
        "--profile",
        developmentPath(origin.origin),
        "--discovery-url",
        `${origin.origin}${DISCOVERY_PATH}`,
        ...extra,
    );
}

// ---------------------------------------------------------------------------------------------------------------
// A stubbed global fetch for the production rows (no network).

type FetchStub = ReturnType<typeof vi.fn<(input: string, init?: RequestInit) => Promise<Response>>>;

function stubFetch(routes: Readonly<Record<string, () => Response>>): FetchStub {
    const fetch = vi.fn((input: string): Promise<Response> => {
        const route = routes[input];
        return route === undefined
            ? Promise.reject(new TypeError("fetch failed"))
            : Promise.resolve(route());
    });
    vi.stubGlobal("fetch", fetch);
    return fetch;
}

const jsonResponse = (value: unknown): (() => Response) => {
    return () => new Response(JSON.stringify(value), { status: 200 });
};

function stubGoogle(discovery: Record<string, unknown> = {}): FetchStub {
    return stubFetch({
        [GOOGLE_DISCOVERY_URL]: jsonResponse({
            issuer: GOOGLE_ISSUER,
            jwks_uri: GOOGLE_JWKS_URI,
            ...discovery,
        }),
        [GOOGLE_JWKS_URI]: jsonResponse({ keys: [RSA_KEY, { ...RSA_KEY, kid: "k2" }] }),
    });
}

const fetchedUrls = (fetch: FetchStub): string[] => fetch.mock.calls.map(([url]) => url);

const PRODUCTION_OK = `ok issuer=${GOOGLE_ISSUER} jwks_uri=${GOOGLE_JWKS_URI} keys=2`;

// ---------------------------------------------------------------------------------------------------------------

describe("row environment: NODE_TLS_REJECT_UNAUTHORIZED=0 → INSECURE_TLS_ENVIRONMENT, exit 2, no network", () => {
    it.each<string[]>([
        ["check-discovery", "--profile", "unused.json"],
        [],
        ["check-discovery", "--offline"],
    ])("argv %j", async (...argv) => {
        vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
        const fetch = stubGoogle();
        expect(await cli(...argv)).toEqual([2, [], ["INSECURE_TLS_ENVIRONMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });

    it.each(["1", "", "00"])(
        "NODE_TLS_REJECT_UNAUTHORIZED=%j is not the refusal value",
        async (value) => {
            vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", value);
            stubGoogle();
            expect(await cli("check-discovery", "--profile", PRODUCTION_PATH())).toEqual([
                0,
                [PRODUCTION_OK],
                [],
            ]);
        },
    );
});

describe("row arguments → INVALID_ARGUMENT, exit 2", () => {
    it.each<string[]>([
        [],
        ["check"],
        ["--profile", "p.json"],
        ["check-discovery"],
        ["check-discovery", "--profile"],
        ["check-discovery", "--profile", "a.json", "--profile", "a.json"],
        ["check-discovery", "--profile", "a.json", "--skip-verification"],
        ["check-discovery", "--profile", "a.json", "--offline"],
        ["check-discovery", "--profile", "a.json", "--allow-mismatch"],
        ["check-discovery", "--profile", "a.json", "extra"],
        ["check-discovery", "--profile=a.json"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "0"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "60001"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "1.5"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "-5"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "01"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "1e3"],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", ""],
        ["check-discovery", "--profile", "a.json", "--timeout-ms", "5", "--timeout-ms", "5"],
        ["check-discovery", "--discovery-url", GOOGLE_DISCOVERY_URL],
    ])("argv %j", async (...argv) => {
        const fetch = stubGoogle();
        expect(await cli(...argv)).toEqual([2, [], ["INVALID_ARGUMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });

    it.each(["1", "60000"])("--timeout-ms %s is accepted", async (value) => {
        const fetch = stubFetch({});
        expect(
            await cli("check-discovery", "--profile", PRODUCTION_PATH(), "--timeout-ms", value),
        ).toEqual([1, [], ["DISCOVERY_UNAVAILABLE"]]);
        expect(fetch).toHaveBeenCalledTimes(1);
    });
});

describe("row profile → INVALID_PROFILE, exit 2", () => {
    it.each<[string, () => string]>([
        ["a missing file", () => join(dir, "absent.json")],
        ["a directory", () => dir],
        ["65537 bytes", () => writeFile(FIXTURE_TEXT.padEnd(65537, " "))],
        ["invalid UTF-8", () => writeFile(new Uint8Array([0x7b, 0xff, 0x7d]))],
        ["non-JSON", () => writeFile("{profile")],
        ["a v1 profile", () => writeFile(JSON.stringify({ profile_version: 1 }))],
        [
            "an unsupported token type",
            () => writeFile(JSON.stringify({ ...PRODUCTION_JSON, token_type: "PKI" })),
        ],
    ])("%s", async (_name, path) => {
        const fetch = stubGoogle();
        expect(await cli("check-discovery", "--profile", path())).toEqual([
            2,
            [],
            ["INVALID_PROFILE"],
        ]);
        expect(fetch).not.toHaveBeenCalled();
    });

    it("reads a profile of exactly 65536 bytes", async () => {
        stubGoogle();
        const path = writeFile(FIXTURE_TEXT.padEnd(65536, " "));
        expect(await cli("check-discovery", "--profile", path)).toEqual([0, [PRODUCTION_OK], []]);
    });
});

describe("row discovery URL", () => {
    it("production without --discovery-url uses GOOGLE_DISCOVERY_URL: exact success line", async () => {
        const fetch = stubGoogle();
        expect(await cli("check-discovery", "--profile", PRODUCTION_PATH())).toEqual([
            0,
            [PRODUCTION_OK],
            [],
        ]);
        expect(fetchedUrls(fetch)).toEqual([GOOGLE_DISCOVERY_URL, GOOGLE_JWKS_URI]);
    });

    it("production with --discovery-url equal to GOOGLE_DISCOVERY_URL", async () => {
        stubGoogle();
        expect(
            await cli(
                "check-discovery",
                "--discovery-url",
                GOOGLE_DISCOVERY_URL,
                "--profile",
                PRODUCTION_PATH(),
            ),
        ).toEqual([0, [PRODUCTION_OK], []]);
    });

    it.each([
        `${GOOGLE_DISCOVERY_URL}/`,
        "https://accounts.google.com/.well-known/openid-configuration",
        "http://127.0.0.1:9/.well-known/openid-configuration",
    ])("production with --discovery-url %s → INVALID_ARGUMENT before any fetch", async (url) => {
        const fetch = stubGoogle();
        expect(
            await cli("check-discovery", "--profile", PRODUCTION_PATH(), "--discovery-url", url),
        ).toEqual([2, [], ["INVALID_ARGUMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });

    it("development without --discovery-url → INVALID_ARGUMENT", async () => {
        const fetch = stubGoogle();
        expect(
            await cli("check-discovery", "--profile", developmentPath("http://127.0.0.1:9")),
        ).toEqual([2, [], ["INVALID_ARGUMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });
});

describe("row --probe-cors → INVALID_ARGUMENT, exit 2", () => {
    it.each([
        "http://example.com",
        "https://a.example/",
        "https://A.example",
        "https://u@a.example",
        "ftp://127.0.0.1",
        "http://10.0.0.1",
        "not a url",
        "null",
        "",
    ])("origin %j", async (origin) => {
        const fetch = stubGoogle();
        expect(
            await cli("check-discovery", "--profile", PRODUCTION_PATH(), "--probe-cors", origin),
        ).toEqual([2, [], ["INVALID_ARGUMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });
});

describe("row binding: the DiscoveryBindingErrorCode on stderr", () => {
    it("a discovery jwks_uri with a trailing slash → JWKS_URI_MISMATCH, exit 1", async () => {
        await withOrigin({}, async (origin) => {
            origin.behaviour.discoveryJwksUri = `${origin.origin}/jwks/`;
            expect(await devRun(origin)).toEqual([1, [], ["JWKS_URI_MISMATCH"]]);
        });
    });

    it("an issuer with a trailing slash → ISSUER_MISMATCH, exit 1", async () => {
        await withOrigin({ issuer: `${DEV_ISSUER}/` }, async (origin) => {
            expect(await devRun(origin)).toEqual([1, [], ["ISSUER_MISMATCH"]]);
        });
    });

    it("an unreachable production discovery → DISCOVERY_UNAVAILABLE, exit 1", async () => {
        stubFetch({});
        expect(await cli("check-discovery", "--profile", PRODUCTION_PATH())).toEqual([
            1,
            [],
            ["DISCOVERY_UNAVAILABLE"],
        ]);
    });

    it("development discovery on another origin → INVALID_ARGUMENT, exit 2", async () => {
        const fetch = stubGoogle();
        expect(
            await cli(
                "check-discovery",
                "--profile",
                developmentPath("http://127.0.0.1:9"),
                "--discovery-url",
                `http://127.0.0.1:10${DISCOVERY_PATH}`,
            ),
        ).toEqual([2, [], ["INVALID_ARGUMENT"]]);
        expect(fetch).not.toHaveBeenCalled();
    });

    it("the binding uses FetchFetcher with the 65536-byte bound", async () => {
        stubFetch({
            [GOOGLE_DISCOVERY_URL]: jsonResponse({
                issuer: GOOGLE_ISSUER,
                jwks_uri: GOOGLE_JWKS_URI,
            }),
            [GOOGLE_JWKS_URI]: () => new Response(new Uint8Array(65537).fill(0x20)),
        });
        expect(await cli("check-discovery", "--profile", PRODUCTION_PATH())).toEqual([
            1,
            [],
            ["JWKS_UNAVAILABLE"],
        ]);
    });

    it("a JWKS of exactly 65536 bytes is accepted (maxDocumentBytes 65536)", async () => {
        const jwks = JSON.stringify({ keys: [RSA_KEY] }).padEnd(65536, " ");
        stubFetch({
            [GOOGLE_DISCOVERY_URL]: jsonResponse({
                issuer: GOOGLE_ISSUER,
                jwks_uri: GOOGLE_JWKS_URI,
            }),
            [GOOGLE_JWKS_URI]: () => new Response(jwks),
        });
        expect(await cli("check-discovery", "--profile", PRODUCTION_PATH())).toEqual([
            0,
            [`ok issuer=${GOOGLE_ISSUER} jwks_uri=${GOOGLE_JWKS_URI} keys=1`],
            [],
        ]);
    });

    it("a development binding against a local origin succeeds with the exact line", async () => {
        await withOrigin({}, async (origin) => {
            expect(await devRun(origin)).toEqual([
                0,
                [`ok issuer=${DEV_ISSUER} jwks_uri=${origin.origin}/jwks keys=1`],
                [],
            ]);
            expect(origin.recorded.map((r) => r.url)).toEqual([DISCOVERY_PATH, "/jwks"]);
        });
    });
});

describe("--timeout-ms bounds every fetch (default 10000)", () => {
    function hangingFetch(): void {
        vi.stubGlobal(
            "fetch",
            vi.fn(
                (_input: string, init?: RequestInit) =>
                    new Promise<Response>((_resolve, reject) => {
                        init?.signal?.addEventListener("abort", () => {
                            reject(new Error("aborted"));
                        });
                    }),
            ),
        );
    }

    it("defaults to 10000 ms", async () => {
        vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
        hangingFetch();
        let settled: [number, string[], string[]] | undefined;
        const running = cli("check-discovery", "--profile", PRODUCTION_PATH()).then((r) => {
            settled = r;
        });
        await vi.advanceTimersByTimeAsync(9999);
        expect(settled).toBeUndefined();
        await vi.advanceTimersByTimeAsync(1);
        await running;
        expect(settled).toEqual([1, [], ["DISCOVERY_UNAVAILABLE"]]);
    });

    it("uses the given value", async () => {
        vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
        hangingFetch();
        let settled: [number, string[], string[]] | undefined;
        const running = cli(
            "check-discovery",
            "--profile",
            PRODUCTION_PATH(),
            "--timeout-ms",
            "250",
        ).then((r) => {
            settled = r;
        });
        await vi.advanceTimersByTimeAsync(249);
        expect(settled).toBeUndefined();
        await vi.advanceTimersByTimeAsync(1);
        await running;
        expect(settled).toEqual([1, [], ["DISCOVERY_UNAVAILABLE"]]);
    });
});

describe("row CORS probe (local node:http origins)", () => {
    it("JWKS echoes the origin, discovery has no ACAO: success line with jwks_acao and discovery_acao=absent", async () => {
        await withOrigin({ jwksAcao: PROBE_ORIGIN }, async (origin) => {
            expect(await devRun(origin, "--probe-cors", PROBE_ORIGIN)).toEqual([
                0,
                [
                    `ok issuer=${DEV_ISSUER} jwks_uri=${origin.origin}/jwks keys=1 jwks_acao=${PROBE_ORIGIN} discovery_acao=absent`,
                ],
                [],
            ]);
            // Four GETs: discovery, JWKS, then the two probes; each probe sends only Origin (plus Host).
            expect(origin.recorded.map((r) => [r.method, r.url])).toEqual([
                ["GET", DISCOVERY_PATH],
                ["GET", "/jwks"],
                ["GET", "/jwks"],
                ["GET", DISCOVERY_PATH],
            ]);
            for (const probe of origin.probes) {
                const names = probe.rawHeaders.filter((_v, i) => i % 2 === 0);
                expect(names.map((n) => n.toLowerCase()).sort()).toEqual(["host", "origin"]);
                expect(
                    probe.rawHeaders[probe.rawHeaders.findIndex((h) => h === "Origin") + 1],
                ).toBe(PROBE_ORIGIN);
            }
            expect(origin.probes).toHaveLength(2);
        });
    });

    it("JWKS ACAO * is accepted; a printable discovery ACAO is reported", async () => {
        await withOrigin({ jwksAcao: "*", discoveryAcao: "*" }, async (origin) => {
            const [code, out] = await devRun(origin, "--probe-cors", PROBE_ORIGIN);
            expect(code).toBe(0);
            expect(out[0]?.endsWith(" jwks_acao=* discovery_acao=*")).toBe(true);
        });
    });

    it.each<[string, string | readonly string[], string]>([
        ["a value with a space", "a b", "invalid"],
        ["duplicated headers (joined)", [PROBE_ORIGIN, PROBE_ORIGIN], "invalid"],
        ["257 printable characters", "x".repeat(257), "invalid"],
        ["256 printable characters", "x".repeat(256), "x".repeat(256)],
        ["an empty value", "", "invalid"],
    ])("discovery ACAO %s → discovery_acao=%s", async (_name, acao, shown) => {
        await withOrigin({ jwksAcao: PROBE_ORIGIN, discoveryAcao: acao }, async (origin) => {
            const [code, out] = await devRun(origin, "--probe-cors", PROBE_ORIGIN);
            expect(code).toBe(0);
            expect(out).toHaveLength(1);
            expect(out[0]?.endsWith(` jwks_acao=${PROBE_ORIGIN} discovery_acao=${shown}`)).toBe(
                true,
            );
        });
    });

    it.each<[string, OriginBehaviour]>([
        ["no ACAO", {}],
        ["another origin", { jwksAcao: "http://127.0.0.1:5556" }],
        ["the origin with a trailing slash", { jwksAcao: `${PROBE_ORIGIN}/` }],
        ["duplicated ACAO headers", { jwksAcao: [PROBE_ORIGIN, PROBE_ORIGIN] }],
        ["status 404 with the echo", { jwksAcao: PROBE_ORIGIN, jwksProbeStatus: 404 }],
        ["a redirect with the echo", { jwksAcao: PROBE_ORIGIN, jwksProbeStatus: 302 }],
        ["a reset connection", { jwksProbe: "reset" }],
        ["a body cut short after the echo", { jwksAcao: PROBE_ORIGIN, jwksProbe: "truncated" }],
    ])("JWKS probe with %s → CORS_MISSING, exit 1", async (_name, behaviour) => {
        await withOrigin(behaviour, async (origin) => {
            expect(await devRun(origin, "--probe-cors", PROBE_ORIGIN)).toEqual([
                1,
                [],
                ["CORS_MISSING"],
            ]);
            expect(origin.recorded.some((r) => r.url === "/moved")).toBe(false);
        });
    });

    it("a JWKS probe that never answers → CORS_MISSING within --timeout-ms", async () => {
        await withOrigin({ jwksProbe: "hang" }, async (origin) => {
            expect(
                await devRun(origin, "--probe-cors", PROBE_ORIGIN, "--timeout-ms", "200"),
            ).toEqual([1, [], ["CORS_MISSING"]]);
        });
    });

    it("an endless JWKS probe body is discarded after the bound, not read to the end", async () => {
        await withOrigin({ jwksAcao: PROBE_ORIGIN, jwksProbe: "endless" }, async (origin) => {
            const [code, out] = await devRun(
                origin,
                "--probe-cors",
                PROBE_ORIGIN,
                "--timeout-ms",
                "5000",
            );
            expect(code).toBe(0);
            expect(out[0]?.endsWith(` jwks_acao=${PROBE_ORIGIN} discovery_acao=absent`)).toBe(true);
        });
    });

    it.each<["hang" | "reset"]>([["hang"], ["reset"]])(
        "the discovery probe is informational: %s → discovery_acao=absent, exit 0",
        async (mode) => {
            await withOrigin({ jwksAcao: PROBE_ORIGIN, discoveryProbe: mode }, async (origin) => {
                const [code, out] = await devRun(
                    origin,
                    "--probe-cors",
                    PROBE_ORIGIN,
                    "--timeout-ms",
                    "200",
                );
                expect(code).toBe(0);
                expect(out[0]?.endsWith(" discovery_acao=absent")).toBe(true);
            });
        },
    );

    it("an https JWKS URI is probed over node:https (a closed loopback port → CORS_MISSING)", async () => {
        const jwksOrigin = "https://127.0.0.1:1";
        stubFetch({
            [`${jwksOrigin}${DISCOVERY_PATH}`]: jsonResponse({
                issuer: DEV_ISSUER,
                jwks_uri: `${jwksOrigin}/jwks`,
            }),
            [`${jwksOrigin}/jwks`]: jsonResponse({ keys: [RSA_KEY] }),
        });
        expect(
            await cli(
                "check-discovery",
                "--profile",
                developmentPath(jwksOrigin),
                "--discovery-url",
                `${jwksOrigin}${DISCOVERY_PATH}`,
                "--probe-cors",
                "https://ci.teecustody.invalid",
                "--timeout-ms",
                "2000",
            ),
        ).toEqual([1, [], ["CORS_MISSING"]]);
    });
});

describe("TL-10: main writes only through io", () => {
    it("never writes to process.stdout or process.stderr and never calls process.exit", async () => {
        const stdout = vi.spyOn(process.stdout, "write");
        const stderr = vi.spyOn(process.stderr, "write");
        const exit = vi.spyOn(process, "exit");
        stubGoogle();
        await cli("check-discovery", "--profile", PRODUCTION_PATH());
        await cli("check-discovery");
        expect(stdout).not.toHaveBeenCalled();
        expect(stderr).not.toHaveBeenCalled();
        expect(exit).not.toHaveBeenCalled();
    });

    it("no output line ever contains a document body", async () => {
        await withOrigin({ jwksAcao: PROBE_ORIGIN }, async (origin) => {
            const [, out, err] = await devRun(origin, "--probe-cors", PROBE_ORIGIN);
            expect([...out, ...err].join("\n")).not.toContain("AQAB");
        });
    });
});
