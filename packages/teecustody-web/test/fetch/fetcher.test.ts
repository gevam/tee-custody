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
