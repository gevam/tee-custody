// FetchFetcher (INC-2-API §8.2, §16.8; B-06; ADR 0009 rules 3, 9; D2-14). T-18 criteria 1-8.
import { CapabilityError } from "@teecustody/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FetchFetcher, type FetchFn } from "../../src/fetch/fetcher.js";

const URL_OK = "https://jwks.example/v1/keys";

interface Call {
    readonly url: string;
    readonly init: RequestInit;
}

function spy(respond: () => Response): { fetch: FetchFn; calls: Call[] } {
    const calls: Call[] = [];
    const fetch: FetchFn = (url, init) => {
        calls.push({ url, init });
        return Promise.resolve(respond());
    };
    return { fetch, calls };
}

function make(fetch: FetchFn, maxBodyBytes = 1024, timeoutMs = 1000): FetchFetcher {
    return new FetchFetcher({ maxBodyBytes, timeoutMs, fetch });
}

afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
});

describe("criterion 1: a canonical https GET with exactly the CORS-simple RequestInit", () => {
    it("resolves {status: 200, body} and passes exactly the §8.2 step 2 members, no headers", async () => {
        const { fetch, calls } = spy(() => new Response(new Uint8Array([7, 8, 9])));
        const result = await make(fetch).get(URL_OK);

        expect(result.status).toBe(200);
        expect(Array.from(result.body)).toEqual([7, 8, 9]);
        expect(calls).toHaveLength(1);
        expect(calls[0]?.url).toBe(URL_OK);
        const init = calls[0]?.init ?? {};
        expect(Object.keys(init).sort()).toEqual(
            ["cache", "credentials", "method", "redirect", "referrerPolicy", "signal"].sort(),
        );
        expect(init.method).toBe("GET");
        expect(init.redirect).toBe("manual");
        expect(init.credentials).toBe("omit");
        expect(init.cache).toBe("no-store");
        expect(init.referrerPolicy).toBe("no-referrer");
        expect(init.signal).toBeInstanceOf(AbortSignal);
        expect("headers" in init).toBe(false);
    });
});

async function rejection(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => new Error("expected a rejection"),
        (error: unknown) => error,
    );
}

function codeOf(error: unknown): string {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

describe("criterion 2: only canonical https (or loopback http) URLs are fetched", () => {
    it.each([
        ["non-canonical host case", "https://Example.com/x"],
        ["userinfo", "https://u:p@a.example/"],
        ["fragment", "https://a.example/#f"],
        ["plain http", "http://a.example/"],
        ["ftp", "ftp://a.example/"],
        ["not a URL", "not a url"],
    ])("%s -> INVALID_ARGUMENT and fetch is never called", async (_name, url) => {
        const { fetch, calls } = spy(() => new Response("{}"));
        expect(codeOf(await rejection(make(fetch).get(url)))).toBe("INVALID_ARGUMENT");
        expect(calls).toHaveLength(0);
    });

    it.each(["http://127.0.0.1:8080/x", "http://[::1]:1/x", "http://localhost:1/x"])(
        "loopback http %s is fetched",
        async (url) => {
            const { fetch, calls } = spy(() => new Response("{}"));
            expect((await make(fetch).get(url)).status).toBe(200);
            expect(calls.map((c) => c.url)).toEqual([url]);
        },
    );
});

// A real Response whose read-only `type`, `redirected` or `url` is overridden, as a browser would report them.
function shaped(
    overrides: { type?: ResponseType; redirected?: boolean; url?: string },
    response: Response = new Response("{}"),
): Response {
    for (const [key, value] of Object.entries(overrides)) {
        Object.defineProperty(response, key, { value });
    }
    return response;
}

describe("criterion 3: no redirect is ever followed or accepted (D2-14)", () => {
    it.each<[string, () => Response]>([
        [
            "same-origin 302",
            () => new Response(null, { status: 302, headers: { Location: `${URL_OK}/next` } }),
        ],
        [
            "cross-origin 302",
            () =>
                new Response(null, { status: 302, headers: { Location: "https://evil.example/" } }),
        ],
        ["opaqueredirect, status 0", () => shaped({ type: "opaqueredirect" }, Response.error())],
        ["opaqueredirect reported with a 200", () => shaped({ type: "opaqueredirect" })],
        ["redirected: true with a 200", () => shaped({ redirected: true, url: URL_OK })],
        ["response.url differs from the input", () => shaped({ url: "https://evil.example/keys" })],
    ])("%s -> HTTP_ERROR", async (_name, respond) => {
        const { fetch } = spy(respond);
        expect(codeOf(await rejection(make(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
    });

    it("accepts a response whose url equals the input (positive control)", async () => {
        const { fetch } = spy(() => shaped({ type: "basic", url: URL_OK }));
        expect((await make(fetch).get(URL_OK)).status).toBe(200);
    });
});

interface Probe {
    pulls: number;
    cancelled: boolean;
}

// A pull-driven body (highWaterMark 0: one pull per read) that records pulls and cancellation.
function probedBody(chunks: readonly Uint8Array[]): {
    body: ReadableStream<Uint8Array>;
    probe: Probe;
} {
    const probe: Probe = { pulls: 0, cancelled: false };
    const body = new ReadableStream<Uint8Array>(
        {
            pull(controller) {
                const chunk = chunks[probe.pulls];
                probe.pulls += 1;
                if (chunk === undefined) {
                    controller.close();
                } else {
                    controller.enqueue(chunk);
                }
            },
            cancel() {
                probe.cancelled = true;
            },
        },
        { highWaterMark: 0 },
    );
    return { body, probe };
}

describe("criterion 4: a non-2xx status fails closed and the body is cancelled", () => {
    it.each([404, 500])("status %i -> HTTP_ERROR, body cancelled", async (status) => {
        const { body, probe } = probedBody([new Uint8Array(10)]);
        const { fetch } = spy(() => new Response(body, { status }));
        expect(codeOf(await rejection(make(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
        expect(probe.cancelled).toBe(true);
        expect(probe.pulls).toBe(0);
    });
});

describe("criterion 5: the body is bounded by maxBodyBytes while streaming", () => {
    it("Content-Length of maxBodyBytes + 1 -> INVALID_RESPONSE before any read", async () => {
        const { body, probe } = probedBody([new Uint8Array(10)]);
        const { fetch } = spy(
            () => new Response(body, { status: 200, headers: { "Content-Length": "1025" } }),
        );
        expect(codeOf(await rejection(make(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
        expect(probe.pulls).toBe(0);
        expect(probe.cancelled).toBe(true);
    });

    it("a chunked body crossing the limit in its third chunk -> INVALID_RESPONSE, cancelled, no fourth pull", async () => {
        const { body, probe } = probedBody(Array.from({ length: 10 }, () => new Uint8Array(400)));
        const { fetch } = spy(() => new Response(body, { status: 200 }));
        expect(codeOf(await rejection(make(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
        expect(probe.cancelled).toBe(true);
        expect(probe.pulls).toBe(3);
    });

    it("a streamed body of exactly maxBodyBytes is returned whole, in order", async () => {
        const chunks = [
            new Uint8Array(400).fill(1),
            new Uint8Array(400).fill(2),
            new Uint8Array(224).fill(3),
        ];
        const { body } = probedBody(chunks);
        const { fetch } = spy(
            () => new Response(body, { status: 200, headers: { "Content-Length": "1024" } }),
        );
        const result = await make(fetch, 1024).get(URL_OK);
        expect(Array.from(result.body)).toEqual(chunks.flatMap((c) => Array.from(c)));
    });
});

describe("decision: a null body resolves an empty Uint8Array", () => {
    it("204 with no body -> {status: 204, body: empty}", async () => {
        const { fetch } = spy(() => new Response(null, { status: 204 }));
        const result = await make(fetch).get(URL_OK);
        expect(result.status).toBe(204);
        expect(result.body).toEqual(new Uint8Array(0));
    });
});

describe("criterion 6: network failure and timeout are UNAVAILABLE", () => {
    it("a fetch that never resolves -> UNAVAILABLE after timeoutMs, and the request is aborted", async () => {
        vi.useFakeTimers();
        const calls: Call[] = [];
        const never: FetchFn = (url, init) => {
            calls.push({ url, init });
            return new Promise<Response>(() => undefined);
        };
        let settled: unknown = "pending";
        const pending = rejection(make(never, 1024, 500).get(URL_OK)).then((error) => {
            settled = error;
        });
        await vi.advanceTimersByTimeAsync(499);
        expect(settled).toBe("pending");
        expect(calls[0]?.init.signal?.aborted).toBe(false);
        await vi.advanceTimersByTimeAsync(1);
        await pending;
        expect(codeOf(settled)).toBe("UNAVAILABLE");
        expect(calls[0]?.init.signal?.aborted).toBe(true);
    });

    it("a rejecting fetch -> UNAVAILABLE", async () => {
        const down: FetchFn = () =>
            Promise.reject(new TypeError("Failed to fetch https://jwks.example/"));
        expect(codeOf(await rejection(make(down).get(URL_OK)))).toBe("UNAVAILABLE");
    });
});

function constructionError(make: () => unknown): unknown {
    try {
        make();
    } catch (error) {
        return error;
    }
    return new Error("expected a throw");
}

describe("criterion 7: both numeric options must be positive safe integers", () => {
    const fetch: FetchFn = () => Promise.resolve(new Response("{}"));
    const bad = [0, -1, 1.5, Number.NaN, 2 ** 53];

    it.each(bad)("maxBodyBytes %s -> TypeError(INVALID_CONFIG)", (value) => {
        const error = constructionError(
            () => new FetchFetcher({ maxBodyBytes: value, timeoutMs: 1000, fetch }),
        );
        expect(error).toBeInstanceOf(TypeError);
        expect((error as Error).message).toBe("INVALID_CONFIG");
    });

    it.each(bad)("timeoutMs %s -> TypeError(INVALID_CONFIG)", (value) => {
        const error = constructionError(
            () => new FetchFetcher({ maxBodyBytes: 1024, timeoutMs: value, fetch }),
        );
        expect(error).toBeInstanceOf(TypeError);
        expect((error as Error).message).toBe("INVALID_CONFIG");
    });

    it("accepts 1 and Number.MAX_SAFE_INTEGER (boundaries)", () => {
        expect(() => new FetchFetcher({ maxBodyBytes: 1, timeoutMs: 1, fetch })).not.toThrow();
        expect(
            () =>
                new FetchFetcher({
                    maxBodyBytes: Number.MAX_SAFE_INTEGER,
                    timeoutMs: Number.MAX_SAFE_INTEGER,
                    fetch,
                }),
        ).not.toThrow();
    });
});

describe("criterion 8: every rejection is CapabilityError(code), message === code, no cause, no URL or body", () => {
    const SECRET_URL = "https://jwks.example/leak-marker-url";
    const SECRET_BODY = "leak-marker-body";
    const text = new TextEncoder().encode(SECRET_BODY);

    function erroringBody(): ReadableStream<Uint8Array> {
        let sent = false;
        return new ReadableStream<Uint8Array>({
            pull(controller) {
                if (sent) {
                    controller.error(new Error(`${SECRET_URL} ${SECRET_BODY}`));
                } else {
                    sent = true;
                    controller.enqueue(text);
                }
            },
        });
    }

    it.each<[string, string, FetchFn]>([
        [
            "INVALID_ARGUMENT",
            `${SECRET_URL}#${SECRET_BODY}`,
            () => Promise.resolve(new Response(text)),
        ],
        [
            "UNAVAILABLE",
            SECRET_URL,
            () => Promise.reject(new TypeError(`${SECRET_URL} ${SECRET_BODY}`)),
        ],
        [
            "HTTP_ERROR",
            SECRET_URL,
            () => Promise.resolve(new Response(text, { status: 500, statusText: SECRET_BODY })),
        ],
        [
            "HTTP_ERROR",
            SECRET_URL,
            () =>
                Promise.resolve(
                    shaped({ url: `https://evil.example/${SECRET_BODY}` }, new Response(text)),
                ),
        ],
        [
            "INVALID_RESPONSE",
            SECRET_URL,
            () => Promise.resolve(new Response(new Uint8Array(2048).fill(0x41))),
        ],
        ["UNAVAILABLE", SECRET_URL, () => Promise.resolve(new Response(erroringBody()))],
    ])("%s carries only its code", async (expected, url, fetch) => {
        const error = await rejection(make(fetch, 1024).get(url));
        expect(error).toBeInstanceOf(CapabilityError);
        const capability = error as CapabilityError;
        expect(capability.code).toBe(expected);
        expect(capability.message).toBe(expected);
        expect("cause" in capability).toBe(false);
        const rendered = `${String(capability)} ${capability.stack ?? ""} ${JSON.stringify(capability)}`;
        expect(rendered).not.toContain("leak-marker");
    });
});

describe("edge: the default fetch is globalThis.fetch", () => {
    it("calls globalThis.fetch with a receiver a browser accepts (no Illegal invocation)", async () => {
        const receivers: unknown[] = [];
        vi.stubGlobal("fetch", function (this: unknown): Promise<Response> {
            receivers.push(this);
            return Promise.resolve(new Response("{}"));
        });
        const result = await new FetchFetcher({ maxBodyBytes: 1024, timeoutMs: 1000 }).get(URL_OK);
        expect(result.status).toBe(200);
        expect(receivers).toHaveLength(1);
        expect(receivers[0] === undefined || receivers[0] === globalThis).toBe(true);
    });
});

describe("decision: a malformed Content-Length is INVALID_RESPONSE before reading", () => {
    it.each(["abc", "-1", "1.5", "1e2", "0x10", "", "10, 10", "+10"])(
        "Content-Length %j -> INVALID_RESPONSE, body cancelled unread",
        async (value) => {
            const { body, probe } = probedBody([new Uint8Array(10)]);
            const { fetch } = spy(
                () => new Response(body, { status: 200, headers: { "Content-Length": value } }),
            );
            expect(codeOf(await rejection(make(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
            expect(probe.pulls).toBe(0);
            expect(probe.cancelled).toBe(true);
        },
    );

    it("a valid Content-Length that understates the body is still caught by the streaming bound", async () => {
        const { body, probe } = probedBody([new Uint8Array(1000), new Uint8Array(1000)]);
        const { fetch } = spy(
            () => new Response(body, { status: 200, headers: { "Content-Length": "10" } }),
        );
        expect(codeOf(await rejection(make(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
        expect(probe.cancelled).toBe(true);
    });
});

describe("edge: a refused redirect releases its body", () => {
    it.each<[string, (body: ReadableStream<Uint8Array>) => Response]>([
        [
            "302",
            (body) =>
                new Response(body, { status: 302, headers: { Location: "https://evil.example/" } }),
        ],
        ["opaqueredirect", (body) => shaped({ type: "opaqueredirect" }, new Response(body))],
        ["redirected", (body) => shaped({ redirected: true }, new Response(body))],
        ["url differs", (body) => shaped({ url: "https://evil.example/" }, new Response(body))],
    ])("%s -> HTTP_ERROR, body cancelled unread", async (_name, respond) => {
        const { body, probe } = probedBody([new Uint8Array(10)]);
        const { fetch } = spy(() => respond(body));
        expect(codeOf(await rejection(make(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
        expect(probe.pulls).toBe(0);
        expect(probe.cancelled).toBe(true);
    });
});

describe("edge: a cancel that rejects is swallowed, never an unhandled rejection", () => {
    // The underlying source's cancel throws, so ReadableStream.cancel() returns a rejected promise.
    function hostileBody(chunks: readonly Uint8Array[]): ReadableStream<Uint8Array> {
        let i = 0;
        return new ReadableStream<Uint8Array>(
            {
                pull(controller) {
                    const chunk = chunks[i];
                    i += 1;
                    if (chunk === undefined) {
                        controller.close();
                    } else {
                        controller.enqueue(chunk);
                    }
                },
                cancel() {
                    throw new Error("cancel failed");
                },
            },
            { highWaterMark: 0 },
        );
    }

    async function settleAndCollectUnhandled(run: () => Promise<unknown>): Promise<unknown[]> {
        const unhandled: unknown[] = [];
        const onUnhandled = (reason: unknown): void => {
            unhandled.push(reason);
        };
        process.on("unhandledRejection", onUnhandled);
        try {
            await run();
            await new Promise((resolve) => setTimeout(resolve, 20));
        } finally {
            process.off("unhandledRejection", onUnhandled);
        }
        return unhandled;
    }

    it.each<[string, string, () => Response]>([
        [
            "500",
            "HTTP_ERROR",
            () => new Response(hostileBody([new Uint8Array(1)]), { status: 500 }),
        ],
        [
            "Content-Length over the bound",
            "INVALID_RESPONSE",
            () =>
                new Response(hostileBody([new Uint8Array(1)]), {
                    headers: { "Content-Length": "4096" },
                }),
        ],
        [
            "streaming overflow",
            "INVALID_RESPONSE",
            () => new Response(hostileBody([new Uint8Array(1000), new Uint8Array(1000)])),
        ],
    ])("%s -> %s with no unhandled rejection", async (_name, expected, respond) => {
        const { fetch } = spy(respond);
        let error: unknown;
        const unhandled = await settleAndCollectUnhandled(async () => {
            error = await rejection(make(fetch, 1024).get(URL_OK));
        });
        expect(codeOf(error)).toBe(expected);
        expect(unhandled).toEqual([]);
    });
});

describe("edge: the timeout also covers body streaming", () => {
    function stallingBody(probe: Probe, cancelThrows: boolean): ReadableStream<Uint8Array> {
        return new ReadableStream<Uint8Array>(
            {
                pull(controller) {
                    probe.pulls += 1;
                    if (probe.pulls === 1) {
                        controller.enqueue(new Uint8Array(10));
                        return undefined;
                    }
                    return new Promise<void>(() => undefined);
                },
                cancel() {
                    probe.cancelled = true;
                    if (cancelThrows) {
                        throw new Error("cancel failed");
                    }
                },
            },
            { highWaterMark: 0 },
        );
    }

    it.each([false, true])(
        "a body that stalls after one chunk -> UNAVAILABLE at timeoutMs, stream cancelled (cancel throws: %s)",
        async (cancelThrows) => {
            vi.useFakeTimers();
            const probe: Probe = { pulls: 0, cancelled: false };
            const { fetch } = spy(() => new Response(stallingBody(probe, cancelThrows)));
            let settled: unknown = "pending";
            const pending = rejection(make(fetch, 1024, 300).get(URL_OK)).then((error) => {
                settled = error;
            });
            await vi.advanceTimersByTimeAsync(299);
            expect(settled).toBe("pending");
            expect(probe.cancelled).toBe(false);
            await vi.advanceTimersByTimeAsync(1);
            await pending;
            expect(codeOf(settled)).toBe("UNAVAILABLE");
            expect(probe.cancelled).toBe(true);
        },
    );
});

describe("edge: a response that arrives after the deadline is released, not read", () => {
    it("fetch resolving after timeoutMs (signal ignored) -> UNAVAILABLE and its body cancelled unread", async () => {
        vi.useFakeTimers();
        const { body, probe } = probedBody([new Uint8Array(10)]);
        const late: FetchFn = () =>
            new Promise<Response>((resolve) => {
                setTimeout(() => {
                    resolve(new Response(body));
                }, 500);
            });
        const pending = rejection(make(late, 1024, 100).get(URL_OK));
        await vi.advanceTimersByTimeAsync(100);
        expect(codeOf(await pending)).toBe("UNAVAILABLE");
        await vi.advanceTimersByTimeAsync(400);
        expect(probe.pulls).toBe(0);
        expect(probe.cancelled).toBe(true);
    });
});

describe("edge: URL and status boundaries", () => {
    it.each([
        ["password-only userinfo", "https://:p@a.example/"],
        ["username-only userinfo", "https://u@a.example/"],
        ["empty fragment", "https://a.example/#"],
        ["upper-case scheme", "HTTPS://a.example/"],
        ["default port spelled out", "https://a.example:443/"],
        ["dot segment", "https://a.example/a/../x"],
        ["loopback lookalike over http", "http://127.0.0.1.evil.example/x"],
        ["shortened loopback literal", "http://127.1:1/x"],
        ["loopback on another scheme", "ws://localhost:1/x"],
    ])("%s -> INVALID_ARGUMENT, never fetched", async (_name, url) => {
        const { fetch, calls } = spy(() => new Response("{}"));
        expect(codeOf(await rejection(make(fetch).get(url)))).toBe("INVALID_ARGUMENT");
        expect(calls).toHaveLength(0);
    });

    it.each([200, 201, 299])("status %i is accepted", async (status) => {
        const { fetch } = spy(() => new Response("{}", { status }));
        expect((await make(fetch).get(URL_OK)).status).toBe(status);
    });

    it.each([199, 300, 304, 600])("status %i -> HTTP_ERROR", async (status) => {
        const { fetch } = spy(() => {
            const response = new Response("{}");
            Object.defineProperty(response, "status", { value: status });
            return response;
        });
        expect(codeOf(await rejection(make(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
    });
});
