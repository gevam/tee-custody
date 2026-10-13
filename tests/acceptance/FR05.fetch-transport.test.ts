// FR-5: FetchTransport, the browser side of the reference gateway contract (INC-2-API 6, 8.3).
// Drives the public class against an injected fetch and against a real loopback HTTP server.
//
// Owning task: T-19 (FetchTransport). Expected failure on trunk: Error("NOT_IMPLEMENTED: T-19").
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { CapabilityError } from "@teecustody/core";
import { FetchTransport, type FetchFn } from "@teecustody/web";
import { afterEach, describe, expect, it } from "vitest";

import { expectThrown } from "./e2e-support.js";

const IID = "ab".repeat(16);
const CID = "cd".repeat(16);
const RID = "ef".repeat(16);
const BASE = "http://127.0.0.1:8099";

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
const json = (value: unknown, status = 200): Response =>
    new Response(JSON.stringify(value), {
        status,
        headers: { "Content-Type": "application/json" },
    });
const text = (body: string, status = 200): Response => new Response(body, { status });

interface Seen {
    url: string;
    init: RequestInit;
}

function scripted(responses: Response[] | ((seen: Seen) => Response | Promise<Response>)): {
    fetch: FetchFn;
    seen: Seen[];
} {
    const seen: Seen[] = [];
    return {
        seen,
        fetch: (input, init) => {
            const entry = { url: input, init };
            seen.push(entry);
            if (typeof responses === "function") {
                return Promise.resolve(responses(entry));
            }
            const next = responses.shift();
            return next === undefined
                ? Promise.reject(new Error("unexpected extra request"))
                : Promise.resolve(next);
        },
    };
}

function transport(fetchFn: FetchFn, extra: Partial<{ baseUrl: string; timeoutMs: number }> = {}) {
    return new FetchTransport({
        baseUrl: extra.baseUrl ?? BASE,
        maxResponseBytes: 4096,
        timeoutMs: extra.timeoutMs ?? 2000,
        fetch: fetchFn,
    });
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function code(error: unknown): string | undefined {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

describe("FR-5 FetchTransport maps the gateway contract", () => {
    it("lists bundles as instance id plus decoded bundle bytes", async () => {
        // Given a gateway answering GET /bundles
        const raw = new Uint8Array([1, 2, 3, 250]);
        const { fetch, seen } = scripted([
            json({ bundles: [{ instance_id: IID, bundle: b64u(raw) }] }),
        ]);
        // When listing
        const bundles = await transport(fetch).listBundles();
        // Then the bytes are decoded, and the request is a credential-less, redirect-refusing GET
        expect(bundles).toHaveLength(1);
        expect(bundles[0]?.instanceId).toBe(IID);
        expect(Array.from(bundles[0]?.bundle ?? [])).toEqual(Array.from(raw));
        expect(seen[0]?.url).toBe(`${BASE}/bundles`);
        expect(seen[0]?.init).toMatchObject({
            method: "GET",
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
        });
    });

    it("posts the envelope as application/octet-stream and returns the relay request id", async () => {
        const { fetch, seen } = scripted([json({ request_id: RID }, 202)]);
        const body = new Uint8Array([9, 8, 7]);
        const id = await transport(fetch).postRequest(IID, body);
        expect(id).toBe(RID);
        expect(seen[0]?.url).toBe(`${BASE}/requests/${IID}`);
        expect(seen[0]?.init.method).toBe("POST");
        expect(new Headers(seen[0]?.init.headers).get("content-type")).toBe(
            "application/octet-stream",
        );
        expect(Array.from(new Uint8Array(seen[0]?.init.body as ArrayBuffer))).toEqual([9, 8, 7]);
        expect(seen[0]?.init).toMatchObject({ redirect: "manual", credentials: "omit" });
    });

    it("polls responses with an optional cursor and maps next:null to undefined", async () => {
        const page = {
            responses: [{ request_id: RID, body: b64u(new Uint8Array([5, 5])) }],
            next: "12",
        };
        const { fetch, seen } = scripted([json(page), json({ responses: [], next: null })]);
        const t = transport(fetch);
        const first = await t.getResponses(CID, "7");
        const second = await t.getResponses(CID);
        expect(seen[0]?.url).toBe(`${BASE}/responses/${CID}?after=7`);
        expect(seen[1]?.url).toBe(`${BASE}/responses/${CID}`);
        expect(first.responses[0]?.requestId).toBe(RID);
        expect(Array.from(first.responses[0]?.body ?? [])).toEqual([5, 5]);
        expect(first.next).toBe("12");
        expect(second.next).toBeUndefined();
    });

    it("keeps a configured path prefix", async () => {
        const { fetch, seen } = scripted([json({ bundles: [] })]);
        await transport(fetch, { baseUrl: `${BASE}/gw` }).listBundles();
        expect(seen[0]?.url).toBe(`${BASE}/gw/bundles`);
    });

    it.each([
        [400, "INVALID_ARGUMENT"],
        [404, "NOT_FOUND"],
        [429, "UNAVAILABLE"],
        [503, "UNAVAILABLE"],
        [500, "INTERNAL"],
        [418, "INTERNAL"],
    ])("maps HTTP %i to %s", async (status, expected) => {
        const { fetch } = scripted([json({ code: "X" }, status)]);
        expect(code(await failure(transport(fetch).listBundles()))).toBe(expected);
    });

    it("treats a network failure and a timeout as UNAVAILABLE", async () => {
        const down: FetchFn = () => Promise.reject(new TypeError("network"));
        expect(code(await failure(transport(down).listBundles()))).toBe("UNAVAILABLE");
        const hang: FetchFn = (_input, init) =>
            new Promise((_resolve, reject) => {
                (init.signal as AbortSignal).addEventListener("abort", () => {
                    reject(new DOMException("aborted", "AbortError"));
                });
            });
        expect(code(await failure(transport(hang, { timeoutMs: 40 }).listBundles()))).toBe(
            "UNAVAILABLE",
        );
    });

    it.each([
        ["unknown key", { bundles: [], extra: 1 }],
        ["wrong shape", { bundles: "x" }],
        ["missing key", {}],
        ["bad instance id", { bundles: [{ instance_id: IID.toUpperCase(), bundle: "AA" }] }],
        ["padded base64url", { bundles: [{ instance_id: IID, bundle: "AQI=" }] }],
        ["standard base64 alphabet", { bundles: [{ instance_id: IID, bundle: "+/+/" }] }],
        ["non-canonical trailing bits", { bundles: [{ instance_id: IID, bundle: "AB" }] }],
        ["extra entry key", { bundles: [{ instance_id: IID, bundle: "AA", x: 1 }] }],
    ])("rejects gateway JSON that is not exactly the contract: %s", async (_name, value) => {
        const { fetch } = scripted([json(value)]);
        expect(code(await failure(transport(fetch).listBundles()))).toBe("INVALID_RESPONSE");
    });

    it("rejects duplicate keys in the gateway JSON", async () => {
        const { fetch } = scripted([text('{"bundles":[],"bundles":[]}')]);
        expect(code(await failure(transport(fetch).listBundles()))).toBe("INVALID_RESPONSE");
    });

    it("rejects a response with an id or cursor outside its pattern", async () => {
        const badId = { responses: [{ request_id: "XYZ", body: "AA" }], next: null };
        const badCursor = { responses: [], next: "no spaces allowed" };
        const { fetch } = scripted([json(badId), json(badCursor)]);
        const t = transport(fetch);
        expect(code(await failure(t.getResponses(CID)))).toBe("INVALID_RESPONSE");
        expect(code(await failure(t.getResponses(CID)))).toBe("INVALID_RESPONSE");
        const badRid = scripted([json({ request_id: "short" }, 202)]);
        expect(
            code(await failure(transport(badRid.fetch).postRequest(IID, new Uint8Array(1)))),
        ).toBe("INVALID_RESPONSE");
    });

    it("refuses an oversize response body", async () => {
        const big = json({ bundles: [], pad: "x".repeat(10_000) });
        const { fetch } = scripted([big]);
        expect(code(await failure(transport(fetch).listBundles()))).toBe("INVALID_RESPONSE");
    });

    it("refuses redirects instead of following them", async () => {
        const redirect = new Response(null, {
            status: 302,
            headers: { Location: `${BASE}/other` },
        });
        const { fetch } = scripted([redirect]);
        expect(code(await failure(transport(fetch).listBundles()))).toBe("INVALID_RESPONSE");
    });

    it.each([
        [
            "instance id uppercase",
            (t: FetchTransport) => t.postRequest(IID.toUpperCase(), new Uint8Array(1)),
        ],
        [
            "instance id short",
            (t: FetchTransport) => t.postRequest(IID.slice(1), new Uint8Array(1)),
        ],
        ["empty body", (t: FetchTransport) => t.postRequest(IID, new Uint8Array(0))],
        ["client id with newline", (t: FetchTransport) => t.getResponses(`${CID}\n`)],
        ["client id traversal", (t: FetchTransport) => t.getResponses("../../x")],
        ["cursor with spaces", (t: FetchTransport) => t.getResponses(CID, "a b")],
        ["cursor too long", (t: FetchTransport) => t.getResponses(CID, "a".repeat(129))],
    ])("rejects invalid arguments before any request: %s", async (_name, call) => {
        const { fetch, seen } = scripted([]);
        expect(code(await failure(call(transport(fetch))))).toBe("INVALID_ARGUMENT");
        expect(seen).toHaveLength(0);
    });

    it.each([
        "http://example.com",
        "ftp://127.0.0.1",
        "/relative",
        "https://user:pw@example.com",
        "https://example.com/?q=1",
        "https://example.com/#f",
        "",
    ])("refuses to be configured with base URL %j", (baseUrl) => {
        expectThrown(
            () => transport(() => Promise.reject(new Error("no")), { baseUrl }),
            new TypeError("INVALID_CONFIG"),
        );
    });

    it("accepts https origins and loopback http", () => {
        const never: FetchFn = () => Promise.reject(new Error("no"));
        expect(() => transport(never, { baseUrl: "https://gateway.example" })).not.toThrow();
        expect(() => transport(never, { baseUrl: "http://localhost:8080" })).not.toThrow();
        expect(() => transport(never, { baseUrl: "http://[::1]:8080" })).not.toThrow();
    });
});

describe("FR-5 FetchTransport against a real loopback gateway", () => {
    let server: Server | undefined;

    afterEach(async () => {
        await new Promise<void>((done) => {
            if (server === undefined) {
                done();
                return;
            }
            server.closeAllConnections();
            server.close(() => {
                done();
            });
        });
        server = undefined;
    });

    async function serve(
        handler: (req: IncomingMessage, res: ServerResponse) => void,
    ): Promise<string> {
        const created = createServer(handler);
        server = created;
        await new Promise<void>((ready) => created.listen(0, "127.0.0.1", ready));
        return `http://127.0.0.1:${String((created.address() as AddressInfo).port)}`;
    }

    function real(baseUrl: string): FetchTransport {
        return new FetchTransport({ baseUrl, maxResponseBytes: 4096, timeoutMs: 2000 });
    }

    it("relays a request body byte for byte and reads the page", async () => {
        const received: Buffer[] = [];
        const origin = await serve((req, res) => {
            if (req.method === "POST") {
                req.on("data", (c: Buffer) => received.push(c));
                req.on("end", () => {
                    res.writeHead(202, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ request_id: RID }));
                });
                return;
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ responses: [], next: null }));
        });
        const t = real(origin);
        const body = new Uint8Array([0, 255, 1, 254]);
        expect(await t.postRequest(IID, body)).toBe(RID);
        expect(Array.from(Buffer.concat(received))).toEqual([0, 255, 1, 254]);
        expect((await t.getResponses(CID)).responses).toHaveLength(0);
    });

    it("does not follow a real redirect, same-origin or cross-origin", async () => {
        let hits = 0;
        const origin = await serve((_req, res) => {
            hits += 1;
            res.writeHead(302, { Location: hits === 1 ? "/bundles2" : "http://127.0.0.1:1/x" });
            res.end();
        });
        const t = real(origin);
        expect(code(await failure(t.listBundles()))).toBe("INVALID_RESPONSE");
        expect(code(await failure(t.listBundles()))).toBe("INVALID_RESPONSE");
        expect(hits).toBe(2);
    });

    it("stops reading a body that grows past the limit", async () => {
        const origin = await serve((_req, res) => {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.write('{"bundles":[],"pad":"');
            const timer = setInterval(() => {
                if (!res.write("x".repeat(1024))) {
                    return;
                }
            }, 5);
            res.on("close", () => {
                clearInterval(timer);
            });
        });
        expect(code(await failure(real(origin).listBundles()))).toBe("INVALID_RESPONSE");
    });
});
