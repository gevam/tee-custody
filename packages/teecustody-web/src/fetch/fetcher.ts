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

// D2-14: with redirect "manual" a browser surfaces a redirect as an opaqueredirect; anything that shows a redirect
// was followed (by a non-conforming fetch) is refused as well. Core cannot see this, so it is enforced here.
function isRedirect(response: Response, url: string): boolean {
    return (
        response.type === "opaqueredirect" ||
        response.redirected ||
        (response.status >= 300 && response.status <= 399) ||
        (response.url !== "" && response.url !== url)
    );
}

// Reads the body chunk by chunk and cancels the stream the moment the running total exceeds the bound.
async function readBounded(
    body: ReadableStream<Uint8Array> | null,
    maxBodyBytes: number,
): Promise<Uint8Array> {
    if (body === null) {
        return new Uint8Array(0);
    }
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
        let chunk: ReadableStreamReadResult<Uint8Array>;
        try {
            chunk = await reader.read();
        } catch {
            throw new CapabilityError("UNAVAILABLE");
        }
        const { done, value } = chunk;
        if (done) {
            break;
        }
        total += value.byteLength;
        if (total > maxBodyBytes) {
            void reader.cancel();
            throw new CapabilityError("INVALID_RESPONSE");
        }
        chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return out;
}

function isPositiveSafeInteger(value: number): boolean {
    return Number.isSafeInteger(value) && value > 0;
}

export class FetchFetcher implements Fetcher {
    readonly #fetch: FetchFn;
    readonly #maxBodyBytes: number;
    readonly #timeoutMs: number;

    // TypeError("INVALID_CONFIG") on bad options
    constructor(options: FetchFetcherOptions) {
        if (!isPositiveSafeInteger(options.maxBodyBytes) || !isPositiveSafeInteger(options.timeoutMs)) {
            throw new TypeError("INVALID_CONFIG");
        }
        this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
        this.#maxBodyBytes = options.maxBodyBytes;
        this.#timeoutMs = options.timeoutMs;
    }

    async get(url: string): Promise<FetchResponse> {
        if (!isAllowedUrl(url)) {
            throw new CapabilityError("INVALID_ARGUMENT");
        }
        const controller = new AbortController();
        let timer: ReturnType<typeof setTimeout> | undefined;
        const deadline = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                controller.abort();
                reject(new CapabilityError("UNAVAILABLE"));
            }, this.#timeoutMs);
        });
        try {
            return await Promise.race([this.#exchange(url, controller.signal), deadline]);
        } finally {
            clearTimeout(timer);
        }
    }

    async #exchange(url: string, signal: AbortSignal): Promise<FetchResponse> {
        let response: Response;
        try {
            response = await this.#fetch(url, {
                method: "GET",
                redirect: "manual",
                credentials: "omit",
                cache: "no-store",
                referrerPolicy: "no-referrer",
                signal,
            });
        } catch {
            throw new CapabilityError("UNAVAILABLE");
        }
        if (isRedirect(response, url)) {
            throw new CapabilityError("HTTP_ERROR");
        }
        if (response.status < 200 || response.status > 299) {
            void response.body?.cancel();
            throw new CapabilityError("HTTP_ERROR");
        }
        if (Number(response.headers.get("Content-Length")) > this.#maxBodyBytes) {
            void response.body?.cancel();
            throw new CapabilityError("INVALID_RESPONSE");
        }
        return { status: response.status, body: await readBounded(response.body, this.#maxBodyBytes) };
    }
}
