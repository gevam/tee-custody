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
    return error instanceof CapabilityError ? error.code : `not a CapabilityError: ${String(error)}`;
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
            () => new Response(null, { status: 302, headers: { Location: "https://evil.example/" } }),
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
function probedBody(chunks: readonly Uint8Array[]): { body: ReadableStream<Uint8Array>; probe: Probe } {
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
        const chunks = [new Uint8Array(400).fill(1), new Uint8Array(400).fill(2), new Uint8Array(224).fill(3)];
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
        const down: FetchFn = () => Promise.reject(new TypeError("Failed to fetch https://jwks.example/"));
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
        ["INVALID_ARGUMENT", `${SECRET_URL}#${SECRET_BODY}`, () => Promise.resolve(new Response(text))],
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
            () => Promise.resolve(shaped({ url: `https://evil.example/${SECRET_BODY}` }, new Response(text))),
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
