// FetchFetcher: the Core Fetcher over fetch (INC-2-API §8.2, §16.8; B-06; ADR 0009 rules 3, 9).
import type { FetchResponse, Fetcher } from "@teecustody/core";

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export interface FetchFetcherOptions {
    readonly maxBodyBytes: number; // positive safe integer; >= VerifierLimits.maxJwksBytes (D-043: no discovery fetch)
    readonly timeoutMs: number; // positive safe integer
    readonly fetch?: FetchFn; // default globalThis.fetch
}

export class FetchFetcher implements Fetcher {
    readonly #fetch: FetchFn;

    // TypeError("INVALID_CONFIG") on bad options
    constructor(options: FetchFetcherOptions) {
        this.#fetch = options.fetch as FetchFn;
    }

    async get(url: string): Promise<FetchResponse> {
        const controller = new AbortController();
        const response = await this.#fetch(url, {
            method: "GET",
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
            signal: controller.signal,
        });
        return { status: response.status, body: new Uint8Array(await response.arrayBuffer()) };
    }
}
