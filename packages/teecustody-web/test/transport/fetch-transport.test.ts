// FetchTransport (INC-2-API §8.3, §6; FR-5; SR-1, SR-3/R-7, SR-5, SR-11). Synthetic values only.
import { CapabilityError } from "@teecustody/core";
import { describe, expect, it } from "vitest";

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

const SAFE_INIT = { redirect: "manual", credentials: "omit", cache: "no-store" };

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
