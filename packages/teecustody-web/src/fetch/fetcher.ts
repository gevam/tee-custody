// FetchFetcher: the Core Fetcher over fetch (INC-2-API §8.2, §16.8; B-06; ADR 0009 rules 3, 9).
import { CapabilityError, type FetchResponse, type Fetcher } from "@teecustody/core";

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export interface FetchFetcherOptions {
    readonly maxBodyBytes: number; // positive safe integer; >= VerifierLimits.maxJwksBytes (D-043: no discovery fetch)
    readonly timeoutMs: number; // positive safe integer
    readonly fetch?: FetchFn; // default globalThis.fetch
}

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]", "localhost"]);

// B-06 canonical form: the URL must survive a WHATWG parse unchanged, carry no userinfo or fragment, and use
// https (http only on a loopback host).
function isAllowedUrl(url: string): boolean {
    let parsed: URL;
    try {
        parsed = new URL(url);
    } catch {
        return false;
    }
    if (parsed.href !== url || parsed.username !== "" || parsed.password !== "" || url.includes("#")) {
        return false;
    }
    return (
        parsed.protocol === "https:" ||
        (parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname))
    );
}

export class FetchFetcher implements Fetcher {
    readonly #fetch: FetchFn;

    // TypeError("INVALID_CONFIG") on bad options
    constructor(options: FetchFetcherOptions) {
        this.#fetch = options.fetch as FetchFn;
    }

    async get(url: string): Promise<FetchResponse> {
        if (!isAllowedUrl(url)) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
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
