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
