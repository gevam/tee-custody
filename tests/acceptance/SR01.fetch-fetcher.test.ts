// SR-1 / B-06 / D-043 §16.8: FetchFetcher, the HTTPS fetcher Core uses for the pinned jwks_uri
// (INC-2-API 8.2), and the RSA modulus rule of the WebCrypto adapter (INC-2-API 8.1).
//
// Owning tasks: T-18 (FetchFetcher), T-17 (createWebCrypto.verifySignature).
// Expected failure on trunk: Error("NOT_IMPLEMENTED: T-18") / Error("NOT_IMPLEMENTED: T-17").
import { constants, createSign, generateKeyPairSync } from "node:crypto";

import { CapabilityError, type RsaPublicJwk } from "@teecustody/core";
import { FetchFetcher, createWebCrypto, type FetchFn } from "@teecustody/web";
import { describe, expect, it } from "vitest";

import { expectThrown } from "./e2e-support.js";

const URL_OK =
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/x@y.iam.gserviceaccount.com";

interface Call {
    url: string;
    init: RequestInit;
}

function recorder(respond: () => Response | Promise<Response>): { fetch: FetchFn; calls: Call[] } {
    const calls: Call[] = [];
    return {
        calls,
        fetch: (url, init) => {
            calls.push({ url, init });
            return Promise.resolve(respond());
        },
    };
}

function fetcher(fetchFn: FetchFn, maxBodyBytes = 1024, timeoutMs = 1000): FetchFetcher {
    return new FetchFetcher({ maxBodyBytes, timeoutMs, fetch: fetchFn });
}

async function failure(promise: Promise<unknown>): Promise<unknown> {
    return promise.then(
        () => undefined,
        (error: unknown) => error,
    );
}

function code(error: unknown): string {
    return error instanceof CapabilityError
        ? error.code
        : `not a CapabilityError: ${String(error)}`;
}

function streaming(
    chunks: Uint8Array[],
    onCancel: () => void,
    headers: HeadersInit = {},
): Response {
    let i = 0;
    const body = new ReadableStream<Uint8Array>({
        pull(controller) {
            const chunk = chunks[i];
            i += 1;
            if (chunk === undefined) {
                controller.close();
            } else {
                controller.enqueue(chunk);
            }
        },
        cancel() {
            onCancel();
        },
    });
    return new Response(body, { status: 200, headers });
}

describe("B-06 FetchFetcher refuses unsafe URLs before any request", () => {
    it.each([
        ["upper-case scheme and host", "HTTPS://WWW.GOOGLEAPIS.COM/x"],
        ["explicit default port", "https://www.googleapis.com:443/x"],
        ["dot segments", "https://www.googleapis.com/a/../x"],
        ["userinfo", "https://user:pw@www.googleapis.com/x"],
        ["fragment", "https://www.googleapis.com/x#frag"],
        ["plain http", "http://www.googleapis.com/x"],
        ["http, loopback lookalike", "http://127.0.0.1.evil.example/x"],
        ["non-url", "not a url"],
        ["ftp", "ftp://www.googleapis.com/x"],
        ["shortened loopback literal", "http://127.1:8791/jwks"],
        ["trailing whitespace", `${URL_OK} `],
    ])("%s -> INVALID_ARGUMENT, fetch never called", async (_name, url) => {
        const { fetch, calls } = recorder(() => new Response("{}"));
        expect(code(await failure(fetcher(fetch).get(url)))).toBe("INVALID_ARGUMENT");
        expect(calls).toHaveLength(0);
    });

    it.each(["http://127.0.0.1:8791/jwks", "http://localhost:8791/jwks", "http://[::1]:8791/jwks"])(
        "allows loopback http: %s",
        async (url) => {
            const { fetch, calls } = recorder(() => new Response('{"keys":[]}'));
            const result = await fetcher(fetch).get(url);
            expect(result.status).toBe(200);
            expect(calls).toHaveLength(1);
        },
    );
});

describe("D-043 §16.8 the request is CORS-simple and carries nothing ambient", () => {
    it("passes exactly the documented RequestInit members and no headers", async () => {
        const { fetch, calls } = recorder(() => new Response('{"keys":[]}'));
        await fetcher(fetch).get(URL_OK);
        expect(calls[0]?.url).toBe(URL_OK);
        const init = calls[0]?.init ?? {};
        expect(Object.keys(init).sort()).toEqual(
            ["cache", "credentials", "method", "redirect", "referrerPolicy", "signal"].sort(),
        );
        expect(init).toMatchObject({
            method: "GET",
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
        });
        expect("headers" in init).toBe(false);
    });
});

describe("B-06 FetchFetcher response handling", () => {
    it("returns the status and the exact body bytes", async () => {
        const { fetch } = recorder(() => new Response(new Uint8Array([1, 2, 3])));
        const result = await fetcher(fetch).get(URL_OK);
        expect(result.status).toBe(200);
        expect(Array.from(result.body)).toEqual([1, 2, 3]);
    });

    it.each([
        [
            "same-origin 302",
            () => new Response(null, { status: 302, headers: { Location: `${URL_OK}2` } }),
        ],
        [
            "cross-origin 302",
            () =>
                new Response(null, { status: 302, headers: { Location: "https://evil.example/" } }),
        ],
        ["307", () => new Response(null, { status: 307 })],
        [
            "opaque redirect",
            () =>
                ({
                    type: "opaqueredirect",
                    status: 0,
                    ok: false,
                    redirected: false,
                    url: "",
                    headers: new Headers(),
                    body: null,
                }) as unknown as Response,
        ],
        [
            "followed redirect",
            () =>
                ({
                    type: "basic",
                    status: 200,
                    ok: true,
                    redirected: true,
                    url: URL_OK,
                    headers: new Headers(),
                    body: null,
                }) as unknown as Response,
        ],
        [
            "response.url differs",
            () =>
                ({
                    type: "basic",
                    status: 200,
                    ok: true,
                    redirected: false,
                    url: "https://evil.example/",
                    headers: new Headers(),
                    body: null,
                }) as unknown as Response,
        ],
    ])("refuses %s with HTTP_ERROR", async (_name, make) => {
        const { fetch } = recorder(make);
        expect(code(await failure(fetcher(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
    });

    it.each([404, 500, 503])(
        "maps status %i to HTTP_ERROR and cancels the body",
        async (status) => {
            let cancelled = false;
            const { fetch } = recorder(() => {
                const r = streaming([new Uint8Array(10)], () => {
                    cancelled = true;
                });
                return new Response(r.body, { status });
            });
            expect(code(await failure(fetcher(fetch).get(URL_OK)))).toBe("HTTP_ERROR");
            expect(cancelled).toBe(true);
        },
    );

    it("rejects a Content-Length over the limit and cancels the stream", async () => {
        let cancelled = false;
        const { fetch } = recorder(() =>
            streaming(
                [new Uint8Array(10)],
                () => {
                    cancelled = true;
                },
                { "Content-Length": "5000" },
            ),
        );
        expect(code(await failure(fetcher(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
        expect(cancelled).toBe(true);
    });

    it("cancels a chunked stream the moment it crosses the limit", async () => {
        let cancelled = false;
        let pulled = 0;
        const { fetch } = recorder(() => {
            const chunks = Array.from({ length: 100 }, () => new Uint8Array(100));
            const r = streaming(chunks, () => {
                cancelled = true;
            });
            pulled += 1;
            return r;
        });
        expect(code(await failure(fetcher(fetch, 1024).get(URL_OK)))).toBe("INVALID_RESPONSE");
        expect(cancelled).toBe(true);
        expect(pulled).toBe(1);
    });

    it("accepts a body of exactly the limit", async () => {
        const { fetch } = recorder(() => new Response(new Uint8Array(1024)));
        expect((await fetcher(fetch, 1024).get(URL_OK)).body).toHaveLength(1024);
    });

    it("treats network failure and timeout as UNAVAILABLE", async () => {
        const down: FetchFn = () => Promise.reject(new TypeError("network down"));
        expect(code(await failure(fetcher(down).get(URL_OK)))).toBe("UNAVAILABLE");
        const hang: FetchFn = (_url, init) =>
            new Promise((_resolve, reject) => {
                (init.signal as AbortSignal).addEventListener("abort", () => {
                    reject(new DOMException("aborted", "AbortError"));
                });
            });
        expect(code(await failure(fetcher(hang, 1024, 40).get(URL_OK)))).toBe("UNAVAILABLE");
    });

    it.each([
        { maxBodyBytes: 0, timeoutMs: 10 },
        { maxBodyBytes: -1, timeoutMs: 10 },
        { maxBodyBytes: 1.5, timeoutMs: 10 },
        { maxBodyBytes: 10, timeoutMs: 0 },
        { maxBodyBytes: Number.MAX_SAFE_INTEGER + 2, timeoutMs: 10 },
        { maxBodyBytes: Number.NaN, timeoutMs: 10 },
    ])("refuses invalid options %j", (options) => {
        expectThrown(() => new FetchFetcher(options), new TypeError("INVALID_CONFIG"));
    });
});

describe("B-06 RSA keys below 2048 bits are refused by the crypto adapter", () => {
    const algorithm = "RSASSA_PKCS1V15_SHA256" as const;
    const data = new TextEncoder().encode("signed bytes");

    function sign(bits: number): { jwk: RsaPublicJwk; signature: Uint8Array } {
        const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
        const jwk = publicKey.export({ format: "jwk" });
        const signer = createSign("RSA-SHA256");
        signer.update(data);
        const signature = signer.sign({ key: privateKey, padding: constants.RSA_PKCS1_PADDING });
        return {
            jwk: { kty: "RSA", n: jwk.n ?? "", e: jwk.e ?? "" },
            signature: new Uint8Array(signature),
        };
    }

    it("refuses a valid 1024-bit signature with INVALID_ARGUMENT", async () => {
        const { jwk, signature } = sign(1024);
        const crypto = createWebCrypto();
        const error = await failure(
            crypto.verifySignature(algorithm, { format: "jwk", jwk }, data, signature),
        );
        expect(code(error)).toBe("INVALID_ARGUMENT");
    });

    it("verifies a 2048-bit signature (positive control) and rejects a tampered one", async () => {
        const { jwk, signature } = sign(2048);
        const crypto = createWebCrypto();
        expect(
            await crypto.verifySignature(algorithm, { format: "jwk", jwk }, data, signature),
        ).toBe(true);
        const bad = signature.slice();
        bad[0] = (bad[0] ?? 0) ^ 1;
        expect(await crypto.verifySignature(algorithm, { format: "jwk", jwk }, data, bad)).toBe(
            false,
        );
    });
});
