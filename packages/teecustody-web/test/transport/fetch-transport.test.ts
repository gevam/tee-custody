// FetchTransport (INC-2-API §8.3, §6; FR-5; SR-1, SR-3/R-7, SR-5, SR-11). Synthetic values only.
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";

import { CapabilityError } from "@teecustody/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FetchFn } from "../../src/fetch/fetcher.js";
import { FetchTransport, type FetchTransportOptions } from "../../src/transport/fetch-transport.js";

const IID = "0123456789abcdef".repeat(2);
const CID = "fedcba9876543210".repeat(2);
const RID = "a5".repeat(16);
const BASE = "https://gw.example/";

interface Call {
    readonly url: string;
    readonly init: RequestInit;
}

function spy(...responses: Response[]): { fetch: FetchFn; calls: Call[] } {
    const calls: Call[] = [];
    return {
        calls,
        fetch: (url, init) => {
            calls.push({ url, init });
            const next = responses.shift();
            return next === undefined
                ? Promise.reject(new Error("unexpected request"))
                : Promise.resolve(next);
        },
    };
}

function json(text: string, status = 200): Response {
    return new Response(text, { status, headers: { "Content-Type": "application/json" } });
}

function make(fetch: FetchFn, options: Partial<FetchTransportOptions> = {}): FetchTransport {
    return new FetchTransport({
        baseUrl: BASE,
        maxResponseBytes: 4096,
        timeoutMs: 1000,
        fetch,
        ...options,
    });
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => new Error("resolved"),
        (error: unknown) => error,
    );
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
    const error = await rejection(promise);
    return error instanceof CapabilityError ? error.code : String(error);
}

const SAFE_INIT = {
    redirect: "manual",
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
};

describe("FetchTransport criterion 1: typed values over credential-less, no-redirect requests", () => {
    it("lists bundles with decoded bytes over a GET with no headers", async () => {
        const { fetch, calls } = spy(
            json(`{"bundles":[{"instance_id":"${IID}","bundle":"AQL_-g"}]}`),
        );
        const bundles = await make(fetch).listBundles();
        expect(bundles).toEqual([{ instanceId: IID, bundle: new Uint8Array([1, 2, 255, 250]) }]);
        expect(calls).toHaveLength(1);
        expect(calls[0]?.url).toBe(`${BASE}bundles`);
        expect(calls[0]?.init).toMatchObject({ method: "GET", ...SAFE_INIT });
        expect(calls[0]?.init.headers).toBeUndefined();
        expect(calls[0]?.init.body).toBeUndefined();
    });

    it("posts an ArrayBuffer copy of the envelope as application/octet-stream", async () => {
        const { fetch, calls } = spy(json(`{"request_id":"${RID}"}`, 202));
        const body = new Uint8Array([7, 0, 9]);
        expect(await make(fetch).postRequest(IID, body)).toBe(RID);
        const init = calls[0]?.init;
        expect(calls[0]?.url).toBe(`${BASE}requests/${IID}`);
        expect(init).toMatchObject({ method: "POST", ...SAFE_INIT });
        expect(new Headers(init?.headers).get("Content-Type")).toBe("application/octet-stream");
        expect(init?.body).toBeInstanceOf(ArrayBuffer);
        const sent = init?.body as ArrayBuffer;
        expect(sent).not.toBe(body.buffer);
        body[0] = 1;
        expect(Array.from(new Uint8Array(sent))).toEqual([7, 0, 9]);
    });

    it("reads a response page with and without a cursor; next null becomes undefined", async () => {
        const { fetch, calls } = spy(
            json(`{"responses":[{"request_id":"${RID}","body":"BQU"}],"next":"c_-9"}`),
            json(`{"next":null,"responses":[]}`),
        );
        const transport = make(fetch);
        const first = await transport.getResponses(CID, "Zz_-0");
        const second = await transport.getResponses(CID);
        expect(first).toEqual({
            responses: [{ requestId: RID, body: new Uint8Array([5, 5]) }],
            next: "c_-9",
        });
        expect(second).toEqual({ responses: [], next: undefined });
        expect(calls.map((c) => c.url)).toEqual([
            `${BASE}responses/${CID}?after=Zz_-0`,
            `${BASE}responses/${CID}`,
        ]);
        for (const call of calls) {
            expect(call.init).toMatchObject({ method: "GET", ...SAFE_INIT });
        }
    });
});

describe("FetchTransport criterion 2: arguments outside the §6 patterns never reach fetch", () => {
    const one = new Uint8Array(1);
    const asString = (value: unknown): string => value as string;
    const asBytes = (value: unknown): Uint8Array => value as Uint8Array;
    const cases: [string, (t: FetchTransport) => Promise<unknown>][] = [
        ["instance 31 chars", (t) => t.postRequest(IID.slice(1), one)],
        ["instance 33 chars", (t) => t.postRequest(`${IID}0`, one)],
        ["instance uppercase", (t) => t.postRequest(IID.toUpperCase(), one)],
        ["instance trailing newline", (t) => t.postRequest(`${IID}\n`, one)],
        ["instance not a string", (t) => t.postRequest(asString([IID]), one)],
        ["client 31 chars", (t) => t.getResponses(CID.slice(1))],
        ["client uppercase", (t) => t.getResponses(CID.toUpperCase())],
        ["client trailing newline", (t) => t.getResponses(`${CID}\n`)],
        ["client traversal", (t) => t.getResponses("../../../../bundles")],
        ["client not a string", (t) => t.getResponses(asString([CID]))],
        ["cursor with slash", (t) => t.getResponses(CID, "a/b")],
        ["cursor with query", (t) => t.getResponses(CID, "a&after=b")],
        ["cursor 129 chars", (t) => t.getResponses(CID, "a".repeat(129))],
        ["cursor empty", (t) => t.getResponses(CID, "")],
        ["cursor trailing newline", (t) => t.getResponses(CID, "a\n")],
        ["cursor not a string", (t) => t.getResponses(CID, asString(["a"]))],
        ["body 0 bytes", (t) => t.postRequest(IID, new Uint8Array(0))],
        ["body 65537 bytes", (t) => t.postRequest(IID, new Uint8Array(65_537))],
        ["body not bytes", (t) => t.postRequest(IID, asBytes("abc"))],
    ];

    it.each(cases)("%s → INVALID_ARGUMENT", async (_name, call) => {
        const { fetch, calls } = spy(json("{}"));
        expect(await codeOf(call(make(fetch)))).toBe("INVALID_ARGUMENT");
        expect(calls).toHaveLength(0);
    });

    it("accepts the boundary values: 1- and 65536-byte bodies, 1- and 128-char cursors", async () => {
        const { fetch, calls } = spy(
            json(`{"request_id":"${RID}"}`, 202),
            json(`{"request_id":"${RID}"}`, 202),
            json(`{"responses":[],"next":null}`),
            json(`{"responses":[],"next":null}`),
        );
        const transport = make(fetch);
        await transport.postRequest(IID, one);
        await transport.postRequest(IID, new Uint8Array(65_536));
        await transport.getResponses(CID, "-");
        await transport.getResponses(CID, "_".repeat(128));
        expect(calls).toHaveLength(4);
        expect((calls[1]?.init.body as ArrayBuffer).byteLength).toBe(65_536);
    });
});

describe("FetchTransport criterion 3: only strict JSON of exactly the §6 shape is accepted", () => {
    const entry = `{"instance_id":"${IID}","bundle":"AQI"}`;
    const reply = `{"request_id":"${RID}","body":"AQI"}`;

    const bundleBodies: [string, string][] = [
        ["invalid JSON", "{"],
        ["empty body", ""],
        ["trailing garbage", `{"bundles":[]}x`],
        ["top-level array", "[]"],
        ["top-level null", "null"],
        ["top-level string", '"bundles"'],
        ["unknown top-level key", `{"bundles":[],"extra":1}`],
        ["missing top-level key", "{}"],
        ["wrong key in place of bundles", `{"bundle":[]}`],
        ["proto key", `{"bundles":[],"__proto__":{}}`],
        ["duplicate top-level key", `{"bundles":[],"bundles":[]}`],
        ["duplicate key, later valid", `{"bundles":[{"x":1}],"bundles":[]}`],
        [
            "duplicate key in entry",
            `{"bundles":[{"instance_id":"${IID}","instance_id":"${IID}","bundle":"AQI"}]}`,
        ],
        [
            "duplicate key in second entry",
            `{"bundles":[${entry},{"bundle":"AQI","instance_id":"${IID}","bundle":"AQI"}]}`,
        ],
        ["escaped key", `{"\\u0062undles":[]}`],
        ["escape in a value", `{"bundles":[{"instance_id":"${IID}","bundle":"A\\u0051I"}]}`],
        ["bundles not an array", `{"bundles":{}}`],
        ["bundles a string", `{"bundles":"x"}`],
        ["entry not an object", `{"bundles":["x"]}`],
        ["entry null", `{"bundles":[null]}`],
        ["entry an array", `{"bundles":[[]]}`],
        ["entry unknown key", `{"bundles":[{"instance_id":"${IID}","bundle":"AQI","x":1}]}`],
        ["entry missing bundle", `{"bundles":[{"instance_id":"${IID}"}]}`],
        [
            "entry key swapped for an unknown one",
            `{"bundles":[{"instance_id":"${IID}","bundlez":"AQI"}]}`,
        ],
        [
            "instance id uppercase",
            `{"bundles":[{"instance_id":"${IID.toUpperCase()}","bundle":"AQI"}]}`,
        ],
        ["instance id short", `{"bundles":[{"instance_id":"${IID.slice(1)}","bundle":"AQI"}]}`],
        ["instance id a number", `{"bundles":[{"instance_id":1,"bundle":"AQI"}]}`],
        ["bundle padded", `{"bundles":[{"instance_id":"${IID}","bundle":"AQI="}]}`],
        ["bundle standard alphabet", `{"bundles":[{"instance_id":"${IID}","bundle":"+/+/"}]}`],
        ["bundle non-zero trailing bits", `{"bundles":[{"instance_id":"${IID}","bundle":"AQJ"}]}`],
        ["bundle dangling digit", `{"bundles":[{"instance_id":"${IID}","bundle":"AQIDB"}]}`],
        ["bundle a number", `{"bundles":[{"instance_id":"${IID}","bundle":12}]}`],
        ["bundle an array", `{"bundles":[{"instance_id":"${IID}","bundle":["AAAA"]}]}`],
    ];

    it.each(bundleBodies)("listBundles: %s → INVALID_RESPONSE", async (_name, text) => {
        const { fetch } = spy(json(text));
        expect(await codeOf(make(fetch).listBundles())).toBe("INVALID_RESPONSE");
    });

    it("listBundles: rejects a body that is not UTF-8", async () => {
        const bytes = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
        const { fetch } = spy(new Response(bytes, { status: 200 }));
        expect(await codeOf(make(fetch).listBundles())).toBe("INVALID_RESPONSE");
    });

    it("listBundles: accepts whitespace, key order and the same key name at different depths", async () => {
        const text = ` { "bundles" : [ ${entry} , {"bundle":"","instance_id":"${RID}"} ] } `;
        const { fetch } = spy(json(text));
        expect(await make(fetch).listBundles()).toEqual([
            { instanceId: IID, bundle: new Uint8Array([1, 2]) },
            { instanceId: RID, bundle: new Uint8Array(0) },
        ]);
    });

    const requestBodies: [string, string][] = [
        ["unknown key", `{"request_id":"${RID}","x":null}`],
        ["missing key", "{}"],
        ["duplicate key", `{"request_id":"${RID}","request_id":"${RID}"}`],
        ["request id uppercase", `{"request_id":"${RID.toUpperCase()}"}`],
        ["request id with newline", `{"request_id":"${RID}\\n"}`],
        ["request id a number", `{"request_id":5}`],
        ["array", `[{"request_id":"${RID}"}]`],
    ];

    it.each(requestBodies)("postRequest: %s → INVALID_RESPONSE", async (_name, text) => {
        const { fetch } = spy(json(text, 202));
        expect(await codeOf(make(fetch).postRequest(IID, new Uint8Array(1)))).toBe(
            "INVALID_RESPONSE",
        );
    });

    const pageBodies: [string, string][] = [
        ["missing next", `{"responses":[]}`],
        ["missing responses", `{"next":null}`],
        ["unknown key", `{"responses":[],"next":null,"more":true}`],
        ["duplicate next", `{"responses":[],"next":null,"next":"abc"}`],
        [
            "duplicate in a reply",
            `{"responses":[{"request_id":"${RID}","body":"AQI","body":"AQI"}],"next":null}`,
        ],
        ["responses not an array", `{"responses":{},"next":null}`],
        ["reply not an object", `{"responses":[1],"next":null}`],
        [
            "reply unknown key",
            `{"responses":[{"request_id":"${RID}","body":"AQI","seq":1}],"next":null}`,
        ],
        ["reply missing body", `{"responses":[{"request_id":"${RID}"}],"next":null}`],
        ["reply bad request id", `{"responses":[{"request_id":"XYZ","body":"AQI"}],"next":null}`],
        ["reply padded body", `{"responses":[{"request_id":"${RID}","body":"AQ=="}],"next":null}`],
        [
            "reply non-canonical body",
            `{"responses":[{"request_id":"${RID}","body":"AR"}],"next":null}`,
        ],
        ["reply body null", `{"responses":[{"request_id":"${RID}","body":null}],"next":null}`],
        ["next with slash", `{"responses":[],"next":"a/b"}`],
        ["next empty", `{"responses":[],"next":""}`],
        ["next 129 chars", `{"responses":[],"next":"${"a".repeat(129)}"}`],
        ["next a number", `{"responses":[],"next":7}`],
        ["next false", `{"responses":[],"next":false}`],
        [
            "page valid but a reply is a duplicate-keyed object",
            `{"responses":[${reply},{"request_id":"${RID}","request_id":"${RID}","body":"AQI"}],"next":null}`,
        ],
    ];

    it.each(pageBodies)("getResponses: %s → INVALID_RESPONSE", async (_name, text) => {
        const { fetch } = spy(json(text));
        expect(await codeOf(make(fetch).getResponses(CID))).toBe("INVALID_RESPONSE");
    });

    it("getResponses: accepts several replies and a 128-char next cursor", async () => {
        const { fetch } = spy(
            json(`{"responses":[${reply},${reply}],"next":"${"Z".repeat(128)}"}`),
        );
        const page = await make(fetch).getResponses(CID);
        expect(page.responses).toHaveLength(2);
        expect(page.next).toBe("Z".repeat(128));
    });
});

function withFields(response: Response, fields: Record<string, unknown>): Response {
    for (const [name, value] of Object.entries(fields)) {
        Object.defineProperty(response, name, { value });
    }
    return response;
}

function trackedBody(text: string): {
    stream: ReadableStream<Uint8Array>;
    cancelled: () => boolean;
} {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(new TextEncoder().encode(text));
        },
        cancel() {
            cancelled = true;
        },
    });
    return { stream, cancelled: () => cancelled };
}

describe("FetchTransport criterion 4: status mapping; redirects are refused, never followed", () => {
    it.each([
        [400, "INVALID_ARGUMENT"],
        [404, "NOT_FOUND"],
        [429, "UNAVAILABLE"],
        [503, "UNAVAILABLE"],
        [500, "INTERNAL"],
        [408, "UNAVAILABLE"],
        [418, "INTERNAL"],
        [201, "INTERNAL"],
        [202, "INTERNAL"],
        [204, "INTERNAL"],
        [302, "INVALID_RESPONSE"],
        [301, "INVALID_RESPONSE"],
        [303, "INVALID_RESPONSE"],
        [307, "INVALID_RESPONSE"],
        [308, "INVALID_RESPONSE"],
        [300, "INVALID_RESPONSE"],
        [399, "INVALID_RESPONSE"],
    ])("listBundles: HTTP %i → %s", async (status, expected) => {
        const body = status === 204 ? null : '{"bundles":[]}';
        const { fetch, calls } = spy(
            new Response(body, { status, headers: { Location: "https://evil.example/" } }),
        );
        expect(await codeOf(make(fetch).listBundles())).toBe(expected);
        expect(calls).toHaveLength(1);
    });

    it("postRequest requires 202 and maps 404 UNKNOWN_INSTANCE to NOT_FOUND", async () => {
        const { fetch } = spy(
            json(`{"request_id":"${RID}"}`, 200),
            json(`{"code":"UNKNOWN_INSTANCE"}`, 404),
            json(`{"code":"INVALID_ARGUMENT"}`, 400),
        );
        const transport = make(fetch);
        const one = new Uint8Array(1);
        expect(await codeOf(transport.postRequest(IID, one))).toBe("INTERNAL");
        expect(await codeOf(transport.postRequest(IID, one))).toBe("NOT_FOUND");
        expect(await codeOf(transport.postRequest(IID, one))).toBe("INVALID_ARGUMENT");
    });

    it("getResponses requires 200 and maps 429 to UNAVAILABLE", async () => {
        const { fetch } = spy(
            json(`{"responses":[],"next":null}`, 202),
            json(`{"code":"RATE_LIMITED"}`, 429),
        );
        const transport = make(fetch);
        expect(await codeOf(transport.getResponses(CID))).toBe("INTERNAL");
        expect(await codeOf(transport.getResponses(CID))).toBe("UNAVAILABLE");
    });

    it.each([
        ["an opaque redirect", { type: "opaqueredirect", status: 0 }],
        ["a followed redirect", { redirected: true }],
        ["a final URL other than the one requested", { url: "https://evil.example/bundles" }],
    ])("refuses %s even with a 200 status", async (_name, fields) => {
        const { fetch } = spy(withFields(json('{"bundles":[]}'), fields));
        expect(await codeOf(make(fetch).listBundles())).toBe("INVALID_RESPONSE");
    });

    it("accepts a final URL equal to the one requested", async () => {
        const { fetch } = spy(withFields(json('{"bundles":[]}'), { url: `${BASE}bundles` }));
        expect(await make(fetch).listBundles()).toEqual([]);
    });

    it("cancels the body of a refused status without reading it", async () => {
        const failed = trackedBody('{"code":"INTERNAL"}');
        const moved = trackedBody("");
        const { fetch } = spy(
            new Response(failed.stream, { status: 500 }),
            new Response(moved.stream, { status: 302 }),
        );
        const transport = make(fetch);
        expect(await codeOf(transport.listBundles())).toBe("INTERNAL");
        expect(await codeOf(transport.listBundles())).toBe("INVALID_RESPONSE");
        expect(failed.cancelled()).toBe(true);
        expect(moved.cancelled()).toBe(true);
    });
});

function endlessBody(chunk: Uint8Array): {
    stream: ReadableStream<Uint8Array>;
    pulls: () => number;
    cancelled: () => boolean;
} {
    let pulls = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>(
        {
            pull(controller) {
                pulls += 1;
                controller.enqueue(chunk.slice());
            },
            cancel() {
                cancelled = true;
            },
        },
        { highWaterMark: 0 },
    );
    return { stream, pulls: () => pulls, cancelled: () => cancelled };
}

describe("FetchTransport criterion 5: response bodies are bounded while streaming", () => {
    it("cancels a streamed body as soon as it crosses maxResponseBytes", async () => {
        const body = endlessBody(new TextEncoder().encode('{"bundles":[]}      '));
        const { fetch } = spy(new Response(body.stream, { status: 200 }));
        const transport = make(fetch, { maxResponseBytes: 50 });
        expect(await codeOf(transport.listBundles())).toBe("INVALID_RESPONSE");
        expect(body.cancelled()).toBe(true);
        expect(body.pulls()).toBe(3);
    });

    it("refuses a declared Content-Length above the limit before reading", async () => {
        const body = endlessBody(new Uint8Array(1));
        const response = new Response(body.stream, {
            status: 200,
            headers: { "Content-Length": "51" },
        });
        const { fetch } = spy(response);
        expect(await codeOf(make(fetch, { maxResponseBytes: 50 }).listBundles())).toBe(
            "INVALID_RESPONSE",
        );
        expect(body.pulls()).toBe(0);
        expect(body.cancelled()).toBe(true);
    });

    it("accepts a body of exactly maxResponseBytes, whatever Content-Length says if not above", async () => {
        const text = '{"bundles":[]}';
        const { fetch } = spy(
            new Response(text, { status: 200, headers: { "Content-Length": String(text.length) } }),
            new Response(text, { status: 200, headers: { "Content-Length": "junk" } }),
        );
        const transport = make(fetch, { maxResponseBytes: text.length });
        expect(await transport.listBundles()).toEqual([]);
        expect(await transport.listBundles()).toEqual([]);
    });

    it("refuses a body one byte over the limit without a Content-Length", async () => {
        const text = '{"bundles":[]} ';
        const { fetch } = spy(new Response(text, { status: 200 }));
        expect(await codeOf(make(fetch, { maxResponseBytes: text.length - 1 }).listBundles())).toBe(
            "INVALID_RESPONSE",
        );
    });

    it("treats a 200 with no body as an invalid response", async () => {
        const { fetch } = spy(new Response(null, { status: 200 }));
        expect(await codeOf(make(fetch).listBundles())).toBe("INVALID_RESPONSE");
    });
});

describe("FetchTransport criterion 6: network failures and timeouts are UNAVAILABLE", () => {
    function hanging(): { fetch: FetchFn; signals: AbortSignal[] } {
        const signals: AbortSignal[] = [];
        return {
            signals,
            fetch: (_url, init) => {
                const signal = init.signal as AbortSignal;
                signals.push(signal);
                return new Promise((_resolve, reject) => {
                    signal.addEventListener("abort", () => {
                        reject(new DOMException("The operation was aborted", "AbortError"));
                    });
                });
            },
        };
    }

    it("maps a rejected fetch to UNAVAILABLE", async () => {
        const down: FetchFn = () => Promise.reject(new TypeError("fetch failed: ECONNREFUSED"));
        expect(await codeOf(make(down).listBundles())).toBe("UNAVAILABLE");
    });

    it("maps a fetch that throws synchronously to UNAVAILABLE", async () => {
        const broken: FetchFn = () => {
            throw new TypeError("bad init");
        };
        expect(await codeOf(make(broken).getResponses(CID))).toBe("UNAVAILABLE");
    });

    it("aborts a request that outlives timeoutMs and reports UNAVAILABLE", async () => {
        const { fetch, signals } = hanging();
        const started = Date.now();
        expect(await codeOf(make(fetch, { timeoutMs: 30 }).listBundles())).toBe("UNAVAILABLE");
        expect(Date.now() - started).toBeGreaterThanOrEqual(25);
        expect(signals[0]?.aborted).toBe(true);
    });

    it("keeps the timeout armed while the body streams", async () => {
        let signal: AbortSignal | undefined;
        const fetch: FetchFn = (_url, init) => {
            signal = init.signal as AbortSignal;
            const stalled = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new TextEncoder().encode('{"bundles":'));
                    signal?.addEventListener("abort", () => {
                        controller.error(new DOMException("aborted", "AbortError"));
                    });
                },
            });
            return Promise.resolve(new Response(stalled, { status: 200 }));
        };
        expect(await codeOf(make(fetch, { timeoutMs: 30 }).listBundles())).toBe("UNAVAILABLE");
        expect(signal?.aborted).toBe(true);
    });

    it("maps a body stream error to UNAVAILABLE", async () => {
        const failing = new ReadableStream<Uint8Array>({
            pull(controller) {
                controller.error(new Error("connection reset"));
            },
        });
        const { fetch } = spy(new Response(failing, { status: 200 }));
        expect(await codeOf(make(fetch).listBundles())).toBe("UNAVAILABLE");
    });

    it("disarms the timer once the exchange completes", async () => {
        const { fetch, calls } = spy(json('{"bundles":[]}'));
        await make(fetch, { timeoutMs: 10 }).listBundles();
        await new Promise((resolve) => setTimeout(resolve, 40));
        expect((calls[0]?.init.signal as AbortSignal).aborted).toBe(false);
    });
});

function configError(options: Partial<FetchTransportOptions>): unknown {
    try {
        make(() => Promise.reject(new Error("unused")), options);
    } catch (error) {
        return error;
    }
    return undefined;
}

describe("FetchTransport criterion 7: configuration is validated at construction", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it.each([
        "http://a.example/",
        "http://a.example",
        "https://A.example",
        "https://a.example/#f",
        "https://a.example/#",
        "https://a.example/?q=1",
        "https://a.example/?",
        "https://a.example/gw?x",
        "https://u@a.example/",
        "https://u:p@a.example/",
        "https://:p@a.example/",
        "https://a.example/gw/../x",
        " https://a.example/",
        "not a url",
        "/relative",
        "",
        "ftp://127.0.0.1/",
        "ws://127.0.0.1/",
        "http://127.0.0.2/",
        "http://localhost.a.example/",
        "http://[::2]/",
    ])("refuses baseUrl %j with TypeError(INVALID_CONFIG)", (baseUrl) => {
        const error = configError({ baseUrl });
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe("INVALID_CONFIG");
    });

    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, "1024"])(
        "refuses maxResponseBytes and timeoutMs of %s",
        (value) => {
            const bad = value as number;
            for (const options of [{ maxResponseBytes: bad }, { timeoutMs: bad }]) {
                const error = configError(options);
                expect(error).toBeInstanceOf(TypeError);
                expect((error as TypeError).message).toBe("INVALID_CONFIG");
            }
        },
    );

    it("refuses a baseUrl that is not a string", () => {
        const error = configError({ baseUrl: new URL(BASE) as unknown as string });
        expect((error as TypeError).message).toBe("INVALID_CONFIG");
    });

    it.each([
        ["https://a.example", "https://a.example/bundles"],
        ["https://a.example/", "https://a.example/bundles"],
        ["https://a.example/gw", "https://a.example/gw/bundles"],
        ["https://a.example/gw/", "https://a.example/gw/bundles"],
        ["https://a.example:8443/a/b", "https://a.example:8443/a/b/bundles"],
        ["http://127.0.0.1:8080", "http://127.0.0.1:8080/bundles"],
        ["http://[::1]:8080", "http://[::1]:8080/bundles"],
        ["http://localhost:8080/", "http://localhost:8080/bundles"],
    ])("accepts baseUrl %j and requests %j", async (baseUrl, expected) => {
        const { fetch, calls } = spy(json('{"bundles":[]}'));
        await make(fetch, { baseUrl }).listBundles();
        expect(calls[0]?.url).toBe(expected);
    });

    it("accepts the smallest limits", async () => {
        const { fetch } = spy(json("{}", 503));
        const transport = make(fetch, { maxResponseBytes: 1, timeoutMs: 1 });
        expect(await codeOf(transport.listBundles())).toBe("UNAVAILABLE");
    });

    it("defaults to globalThis.fetch, looked up at call time", async () => {
        const { fetch, calls } = spy(json('{"bundles":[]}'));
        const transport = new FetchTransport({
            baseUrl: BASE,
            maxResponseBytes: 64,
            timeoutMs: 1000,
        });
        vi.stubGlobal("fetch", fetch);
        expect(await transport.listBundles()).toEqual([]);
        expect(calls[0]?.url).toBe(`${BASE}bundles`);
    });
});

describe("FetchTransport criterion 8: errors carry only their code (SR-11)", () => {
    const SENTINEL_BODY = "c2VjcmV0LWJvZHktYnl0ZXM";
    const SECRET_HOST = "https://secret-host.example/";

    function hostile(message: string): Response {
        const response = json(`{"bundles":[{"instance_id":"${SENTINEL_BODY}"}]}`);
        Object.defineProperty(response, "headers", {
            get(): never {
                throw new Error(message);
            },
        });
        return response;
    }

    const failures: [string, string, () => Promise<unknown>][] = [
        ["INVALID_ARGUMENT", "argument", () => make(spy().fetch).getResponses(SENTINEL_BODY)],
        [
            "INVALID_RESPONSE",
            "body",
            () => make(spy(json(`{"bundles":"${SENTINEL_BODY}"}`)).fetch).listBundles(),
        ],
        [
            "INVALID_RESPONSE",
            "base64url",
            () =>
                make(
                    spy(json(`{"bundles":[{"instance_id":"${IID}","bundle":"${SENTINEL_BODY}="}]}`))
                        .fetch,
                ).listBundles(),
        ],
        [
            "INVALID_RESPONSE",
            "JSON syntax",
            () => make(spy(json(`{"${SENTINEL_BODY}`)).fetch).listBundles(),
        ],
        [
            "UNAVAILABLE",
            "network",
            () =>
                make(() => Promise.reject(new TypeError(`${SECRET_HOST} ${SENTINEL_BODY}`)), {
                    baseUrl: SECRET_HOST,
                }).listBundles(),
        ],
        ["NOT_FOUND", "status", () => make(spy(json(SENTINEL_BODY, 404)).fetch).listBundles()],
        [
            "INTERNAL",
            "hostile response object",
            () =>
                make(spy(hostile(`${SECRET_HOST} ${SENTINEL_BODY}`)).fetch, {
                    baseUrl: SECRET_HOST,
                }).listBundles(),
        ],
        [
            "INTERNAL",
            "fetch resolving to a non-response",
            () => make(() => Promise.resolve(undefined as unknown as Response)).listBundles(),
        ],
    ];

    it.each(failures)(
        "%s (%s): message equals the code, nothing else attached",
        async (expected, _name, run) => {
            const error = await rejection(run());
            expect(error).toBeInstanceOf(CapabilityError);
            const failure = error as CapabilityError;
            expect(failure.code).toBe(expected);
            expect(failure.message).toBe(expected);
            expect(failure.cause).toBeUndefined();
            expect(Object.keys(failure)).toEqual(["code"]);
            const rendered = `${String(failure.stack)} ${JSON.stringify(failure)}`;
            expect(rendered).not.toContain(SENTINEL_BODY);
            expect(rendered).not.toContain("secret-host");
        },
    );

    it("INVALID_CONFIG carries no URL text", () => {
        const error = configError({ baseUrl: "http://secret-host.example/" }) as TypeError;
        expect(error.message).toBe("INVALID_CONFIG");
        expect(String(error.stack)).not.toContain("secret-host");
    });
});

describe("FetchTransport edge cases", () => {
    it("never retries: a failed call makes exactly one request and re-sends nothing", async () => {
        const calls: Call[] = [];
        const fetch: FetchFn = (url, init) => {
            calls.push({ url, init });
            return Promise.reject(new TypeError("reset"));
        };
        expect(await codeOf(make(fetch).postRequest(IID, new Uint8Array([1])))).toBe("UNAVAILABLE");
        expect(calls).toHaveLength(1);
    });

    it("copies exactly the view's bytes, even for a view into a larger buffer", async () => {
        const { fetch, calls } = spy(
            json(`{"request_id":"${RID}"}`, 202),
            json(`{"request_id":"${RID}"}`, 202),
        );
        const backing = new Uint8Array([9, 9, 1, 2, 3, 9, 9]);
        const transport = make(fetch);
        await transport.postRequest(IID, backing.subarray(2, 5));
        await transport.postRequest(IID, Buffer.from([4, 5, 6]));
        const sent = calls.map((call) => Array.from(new Uint8Array(call.init.body as ArrayBuffer)));
        expect(sent).toEqual([
            [1, 2, 3],
            [4, 5, 6],
        ]);
    });

    it("gives concurrent calls independent timers and results", async () => {
        const { fetch } = spy(
            json(`{"request_id":"${RID}"}`, 202),
            json(`{"responses":[],"next":"n"}`),
        );
        const transport = make(fetch);
        const [id, page] = await Promise.all([
            transport.postRequest(IID, new Uint8Array([1])),
            transport.getResponses(CID),
        ]);
        expect(id).toBe(RID);
        expect(page.next).toBe("n");
    });
});

describe("FetchTransport against a real loopback HTTP server", () => {
    let server: Server | undefined;

    afterEach(async () => {
        const running = server;
        server = undefined;
        if (running !== undefined) {
            running.closeAllConnections();
            await new Promise((done) => running.close(done));
        }
    });

    async function serve(
        handler: (req: IncomingMessage, res: ServerResponse) => void,
    ): Promise<string> {
        const created = createServer(handler);
        server = created;
        await new Promise<void>((ready) => created.listen(0, "127.0.0.1", ready));
        return `http://127.0.0.1:${String((created.address() as AddressInfo).port)}/gw`;
    }

    function real(baseUrl: string, timeoutMs = 2000): FetchTransport {
        return new FetchTransport({ baseUrl, maxResponseBytes: 1024, timeoutMs });
    }

    it("relays the body byte for byte with the octet-stream type and no cookies", async () => {
        const seen: {
            url?: string | undefined;
            type?: string | undefined;
            cookie?: string | undefined;
            body: Buffer[];
        } = { body: [] };
        const origin = await serve((req, res) => {
            seen.url = req.url;
            seen.type = req.headers["content-type"];
            seen.cookie = req.headers.cookie;
            req.on("data", (chunk: Buffer) => seen.body.push(chunk));
            req.on("end", () => {
                res.writeHead(202, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ request_id: RID }));
            });
        });
        const body = new Uint8Array([0, 255, 13, 10, 34]);
        expect(await real(origin).postRequest(IID, body)).toBe(RID);
        expect(seen.url).toBe(`/gw/requests/${IID}`);
        expect(seen.type).toBe("application/octet-stream");
        expect(seen.cookie).toBeUndefined();
        expect(Array.from(Buffer.concat(seen.body))).toEqual(Array.from(body));
    });

    it("does not follow a redirect", async () => {
        let hits = 0;
        const origin = await serve((_req, res) => {
            hits += 1;
            res.writeHead(307, { Location: "/gw/bundles-elsewhere" });
            res.end();
        });
        expect(await codeOf(real(origin).listBundles())).toBe("INVALID_RESPONSE");
        expect(hits).toBe(1);
    });

    it("cuts off a body that keeps growing past the limit", async () => {
        const origin = await serve((_req, res) => {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.write('{"bundles":[],"pad":"');
            const timer = setInterval(() => res.write("x".repeat(512)), 2);
            res.on("close", () => {
                clearInterval(timer);
            });
        });
        expect(await codeOf(real(origin).listBundles())).toBe("INVALID_RESPONSE");
    });

    it("times out a body that stalls after the headers", async () => {
        const origin = await serve((_req, res) => {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.write('{"bundles":');
        });
        expect(await codeOf(real(origin, 50).listBundles())).toBe("UNAVAILABLE");
    });
});

// T-42 (D-07; INC-2-API §8.3 amended, §6 "Maximal response sizes"): maxResponseBytes defaults to 2,097,152.

// Unpadded base64url length of `bytes` bytes.
function b64Chars(bytes: number): number {
    const rest = bytes % 3;
    return Math.floor(bytes / 3) * 4 + (rest === 0 ? 0 : rest + 1);
}

const MAX_FRAME_CHARS = b64Chars(32_926);
const MAX_BUNDLE_CHARS = b64Chars(65_536);

function replyItem(chars: number): string {
    return `{"request_id":"${RID}","body":"${"A".repeat(chars)}"}`;
}

function responsesJson(items: readonly string[], next: string): string {
    return `{"responses":[${items.join(",")}],"next":"${next}"}`;
}

// Valid compact §6 GET /responses JSON of exactly `total` bytes: maximal frames, then a last item and the
// `next` cursor (128 or 127 chars) absorbing the remainder. No base64url length is ≡ 1 (mod 4).
function responsesPage(total: number): string {
    const full = replyItem(MAX_FRAME_CHARS).length + 1;
    const overhead = replyItem(0).length;
    let cursor = 128;
    const count = Math.floor(
        (total - responsesJson([], "A".repeat(cursor)).length - overhead) / full,
    );
    let last = total - responsesJson([], "A".repeat(cursor)).length - count * full - overhead;
    if (last % 4 === 1) {
        cursor -= 1;
        last += 1;
    }
    const items = [...Array<string>(count).fill(replyItem(MAX_FRAME_CHARS)), replyItem(last)];
    return responsesJson(items, "A".repeat(cursor));
}

// The §6 maximal GET /responses page at the default max_page 32.
const MAXIMAL_PAGE = responsesJson(
    Array<string>(32).fill(replyItem(MAX_FRAME_CHARS)),
    "A".repeat(128),
);

// The §6 maximal GET /bundles page: 16 bundles at the 65,536-byte decode limit.
const MAXIMAL_BUNDLES = `{"bundles":[${Array<string>(16)
    .fill(`{"instance_id":"${IID}","bundle":"${"A".repeat(MAX_BUNDLE_CHARS)}"}`)
    .join(",")}]}`;

// A body streamed in 64 KiB chunks with no Content-Length; records whether it was cancelled.
function streamed(text: string): { response: Response; cancelled: () => boolean } {
    const bytes = new TextEncoder().encode(text);
    let offset = 0;
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>(
        {
            pull(controller) {
                if (offset >= bytes.byteLength) {
                    controller.close();
                    return;
                }
                controller.enqueue(bytes.slice(offset, offset + 65_536));
                offset += 65_536;
            },
            cancel() {
                cancelled = true;
            },
        },
        { highWaterMark: 0 },
    );
    const response = new Response(stream, { status: 200 });
    return { response, cancelled: () => cancelled };
}

function defaulted(fetch: FetchFn): FetchTransport {
    return new FetchTransport({ baseUrl: BASE, timeoutMs: 1000, fetch });
}

function explicitlyUndefined(fetch: FetchFn): FetchTransport {
    const options = { baseUrl: BASE, maxResponseBytes: undefined, timeoutMs: 1000, fetch };
    // @ts-expect-error exactOptionalPropertyTypes rejects an explicit undefined
    return new FetchTransport(options);
}

describe.each([
    ["omitted", defaulted],
    ["undefined", explicitlyUndefined],
])("FetchTransport T-42 criteria 1 and 3: maxResponseBytes %s means 2,097,152", (_name, build) => {
    it("accepts a streamed page of exactly 2,097,152 bytes", async () => {
        const page = responsesPage(2_097_152);
        expect(page.length).toBe(2_097_152);
        const { response } = streamed(page);
        expect(response.headers.get("Content-Length")).toBeNull();
        const { fetch } = spy(response);
        const result = await build(fetch).getResponses(CID);
        expect(result.responses.length).toBeGreaterThan(32);
        expect(result.next?.length).toBeGreaterThanOrEqual(127);
    });

    it("refuses a streamed page of 2,097,153 bytes and cancels the stream", async () => {
        const page = responsesPage(2_097_153);
        expect(page.length).toBe(2_097_153);
        const body = streamed(page);
        const { fetch } = spy(body.response);
        expect(await codeOf(build(fetch).getResponses(CID))).toBe("INVALID_RESPONSE");
        expect(body.cancelled()).toBe(true);
    });

    it("refuses Content-Length 2097153 before any read, never acquiring a reader", async () => {
        const body = endlessBody(new Uint8Array(1));
        const getReader = vi.spyOn(body.stream, "getReader");
        const response = new Response(body.stream, {
            status: 200,
            headers: { "Content-Length": "2097153" },
        });
        const { fetch } = spy(response);
        expect(await codeOf(build(fetch).getResponses(CID))).toBe("INVALID_RESPONSE");
        expect(getReader).not.toHaveBeenCalled();
        expect(body.pulls()).toBe(0);
        expect(body.cancelled()).toBe(true);
    });
});

describe("FetchTransport T-42 criterion 2: the default covers the §6 maximal pages", () => {
    it("reads the 1,406,937-byte maximal GET /responses page", async () => {
        expect(MAXIMAL_PAGE.length).toBe(1_406_937);
        const { fetch } = spy(streamed(MAXIMAL_PAGE).response);
        const page = await defaulted(fetch).getResponses(CID);
        expect(page.responses).toHaveLength(32);
        for (const reply of page.responses) {
            expect(reply.requestId).toBe(RID);
            expect(reply.body.byteLength).toBe(32_926);
        }
        expect(page.next).toBe("A".repeat(128));
    });

    it("reads the 1,399,133-byte maximal GET /bundles page", async () => {
        expect(MAXIMAL_BUNDLES.length).toBe(1_399_133);
        const { fetch } = spy(streamed(MAXIMAL_BUNDLES).response);
        const bundles = await defaulted(fetch).listBundles();
        expect(bundles).toHaveLength(16);
        for (const entry of bundles) {
            expect(entry.instanceId).toBe(IID);
            expect(entry.bundle.byteLength).toBe(65_536);
        }
    });
});

describe("FetchTransport T-42 criterion 4: an explicit maxResponseBytes still applies", () => {
    it("refuses the 1,406,937-byte maximal page at an explicit 1,048,576 (§6 interoperability rule)", async () => {
        const body = streamed(MAXIMAL_PAGE);
        const { fetch } = spy(body.response);
        expect(await codeOf(make(fetch, { maxResponseBytes: 1_048_576 }).getResponses(CID))).toBe(
            "INVALID_RESPONSE",
        );
        expect(body.cancelled()).toBe(true);
    });

    it("accepts a 2,500,000-byte page at an explicit 3,000,000", async () => {
        const page = responsesPage(2_500_000);
        expect(page.length).toBe(2_500_000);
        const { fetch } = spy(streamed(page).response);
        const result = await make(fetch, { maxResponseBytes: 3_000_000 }).getResponses(CID);
        expect(result.responses.length).toBeGreaterThan(32);
    });
});

describe("FetchTransport T-42 criterion 5: a given maxResponseBytes is validated as before", () => {
    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, "1024", null])(
        "refuses maxResponseBytes %s with TypeError(INVALID_CONFIG)",
        (value) => {
            const error = configError({ maxResponseBytes: value as number });
            expect(error).toBeInstanceOf(TypeError);
            expect((error as TypeError).message).toBe("INVALID_CONFIG");
        },
    );

    it("still requires timeoutMs", () => {
        const options = { baseUrl: BASE, fetch: spy().fetch };
        let error: unknown;
        try {
            new FetchTransport(options as unknown as FetchTransportOptions);
        } catch (thrown) {
            error = thrown;
        }
        expect(error).toBeInstanceOf(TypeError);
        expect((error as TypeError).message).toBe("INVALID_CONFIG");
    });
});

describe("FetchTransport T-42 criterion 6: the default is the contract number, not an export", () => {
    const source = readFileSync(
        fileURLToPath(new URL("../../src/transport/fetch-transport.ts", import.meta.url)),
        "utf8",
    );

    it("states 2_097_152 exactly once in fetch-transport.ts", () => {
        expect(source.split("2_097_152")).toHaveLength(2);
    });

    it("exports no default constant from the module", async () => {
        const module = await import("../../src/transport/fetch-transport.js");
        expect(Object.keys(module)).toEqual(["FetchTransport"]);
    });
});
