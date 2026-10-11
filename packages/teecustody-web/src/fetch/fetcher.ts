// FetchFetcher: the Core Fetcher over fetch (INC-2-API §8.2; B-06; ADR 0009 rules 3, 9). Stub → T-18.
import type { FetchResponse, Fetcher } from "@teecustody/core";

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export interface FetchFetcherOptions {
    readonly maxBodyBytes: number; // positive safe integer; >= VerifierLimits.maxDiscoveryBytes and maxJwksBytes
    readonly timeoutMs: number; // positive safe integer
    readonly fetch?: FetchFn; // default globalThis.fetch
}

export class FetchFetcher implements Fetcher {
    // TypeError("INVALID_CONFIG") on bad options
    constructor(options: FetchFetcherOptions) {
        throw new Error("NOT_IMPLEMENTED: T-18");
    }

    get(url: string): Promise<FetchResponse> {
        throw new Error("NOT_IMPLEMENTED: T-18");
    }
}
