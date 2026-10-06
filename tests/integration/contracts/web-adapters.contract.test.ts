// Contract: @teecustody/web capability adapters against the Core interfaces (FR-5, FR-6, SR-1 B-06,
// SR-3, SR-5, SR-14; INC-2-API §8.1–§8.4, §6; API-TL TL-6). Expected red until T-17, T-18, T-19 and
// T-20 merge (docs/tasks/INC-2/WAVES.md).
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";

import { CapabilityError, type PublicKeyInput } from "@teecustody/core";
import {
    FetchFetcher,
    FetchTransport,
    PrfShareVault,
    createWebCrypto,
    type FetchFn,
} from "@teecustody/web";

const CLIENT = "c1".repeat(16);

interface Call {
    readonly url: string;
    readonly init: RequestInit;
}

function recordingFetch(respond: (url: string) => Response): { fetch: FetchFn; calls: Call[] } {
    const calls: Call[] = [];
    return {
        calls,
        fetch: (url, init) => {
            calls.push({ url, init });
            return Promise.resolve(respond(url));
        },
    };
}

async function codeOf(promise: Promise<unknown>): Promise<string> {
    try {
        await promise;
        return "none";
    } catch (error) {
        if (error instanceof CapabilityError) {
            return error.code;
        }
        throw error;
    }
}

describe("FetchFetcher (B-06)", () => {
    it("rejects non-canonical, credentialed, fragment and plain-http URLs without fetching", async () => {
        const { fetch, calls } = recordingFetch(() => new Response("{}"));
        const fetcher = new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 1_000, fetch });
        for (const url of [
            "https://Issuer.example/x",
            "https://u:p@issuer.example/x",
            "https://issuer.example/x#f",
            "http://issuer.example/x",
        ]) {
            expect(await codeOf(fetcher.get(url)), url).toBe("INVALID_ARGUMENT");
        }
        expect(calls).toEqual([]);
    });

    it("never follows a redirect and sends no credentials", async () => {
        const { fetch, calls } = recordingFetch(
            () =>
                new Response(null, { status: 302, headers: { Location: "https://evil.example/" } }),
        );
        const fetcher = new FetchFetcher({ maxBodyBytes: 65_536, timeoutMs: 1_000, fetch });

        expect(await codeOf(fetcher.get("https://issuer.example/jwks"))).toBe("HTTP_ERROR");
        expect(calls[0]?.init).toMatchObject({
            method: "GET",
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
        });
    });

    it("bounds the body before reading it", async () => {
        const { fetch } = recordingFetch(
            () => new Response("x".repeat(10), { headers: { "Content-Length": "10" } }),
        );
        const fetcher = new FetchFetcher({ maxBodyBytes: 9, timeoutMs: 1_000, fetch });

        expect(await codeOf(fetcher.get("https://issuer.example/jwks"))).toBe("INVALID_RESPONSE");
    });
});

describe("FetchTransport (gateway contract §6)", () => {
    const options = {
        baseUrl: "https://gateway.example/",
        maxResponseBytes: 1_048_576,
        timeoutMs: 1_000,
    };

    it("maps a response page and omits credentials", async () => {
        const { fetch, calls } = recordingFetch(
            () =>
                new Response(
                    JSON.stringify({
                        responses: [{ request_id: "0".repeat(32), body: "AQI" }],
                        next: null,
                    }),
                    { status: 200, headers: { "Content-Type": "application/json" } },
                ),
        );
        const page = await new FetchTransport({ ...options, fetch }).getResponses(CLIENT);

        expect(page.next).toBeUndefined();
        expect(page.responses).toEqual([
            { requestId: "0".repeat(32), body: new Uint8Array([1, 2]) },
        ]);
        expect(calls[0]?.url).toBe(`https://gateway.example/responses/${CLIENT}`);
        expect(calls[0]?.init).toMatchObject({ credentials: "omit", redirect: "manual" });
    });

    it("rejects duplicate keys, bad ids and throttling with the documented codes", async () => {
        const duplicate = recordingFetch(
            () => new Response('{"responses":[],"responses":[],"next":null}', { status: 200 }),
        );
        const throttled = recordingFetch(
            () => new Response('{"code":"RATE_LIMITED"}', { status: 429 }),
        );
        const unused = recordingFetch(() => new Response("{}"));

        expect(
            await codeOf(
                new FetchTransport({ ...options, fetch: duplicate.fetch }).getResponses(CLIENT),
            ),
        ).toBe("INVALID_RESPONSE");
        expect(
            await codeOf(new FetchTransport({ ...options, fetch: throttled.fetch }).listBundles()),
        ).toBe("UNAVAILABLE");
        expect(
            await codeOf(
                new FetchTransport({ ...options, fetch: unused.fetch }).getResponses(`${CLIENT}\n`),
            ),
        ).toBe("INVALID_ARGUMENT");
        expect(unused.calls).toEqual([]);
    });
});

describe("createWebCrypto (ADR 0011)", () => {
    it("refuses an RSA modulus below 2048 bits (B-06)", async () => {
        const pair = await globalThis.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 1024,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["sign", "verify"],
        );
        const jwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
        const key: PublicKeyInput = {
            format: "jwk",
            jwk: { kty: "RSA", n: jwk.n ?? "", e: jwk.e ?? "" },
        };

        expect(
            await codeOf(
                createWebCrypto().verifySignature(
                    "RSASSA_PKCS1V15_SHA256",
                    key,
                    new Uint8Array(1),
                    new Uint8Array(128),
                ),
            ),
        ).toBe("INVALID_ARGUMENT");
    });

    it("agrees on HPKE plaintext and both exports between sender and receiver", async () => {
        const crypto = createWebCrypto();
        const recipient = (await globalThis.crypto.subtle.generateKey({ name: "X25519" }, true, [
            "deriveBits",
        ])) as CryptoKeyPair;
        const pkR = new Uint8Array(
            await globalThis.crypto.subtle.exportKey("raw", recipient.publicKey),
        );
        const skJwk = await globalThis.crypto.subtle.exportKey("jwk", recipient.privateKey);
        const skR = new Uint8Array(Buffer.from(skJwk.d ?? "", "base64url"));
        const info = new TextEncoder().encode("contract-info");
        const aad = new Uint8Array([1, 2, 3]);
        const c2t = new TextEncoder().encode("c2t");

        const sender = await crypto.setupHpkeSender(pkR, info);
        const ct = await sender.seal(aad, new Uint8Array([42]));
        const receiver = await crypto.setupHpkeReceiver(skR, sender.encapsulatedKey, info);

        expect(await receiver.open(aad, ct)).toEqual(new Uint8Array([42]));
        expect(await receiver.export(c2t, 32)).toEqual(await sender.export(c2t, 32));
        expect(await codeOf(receiver.open(new Uint8Array([9]), ct))).toBe("AUTHENTICATION_FAILED");
    });
});

describe("PrfShareVault (FR-6, TL-6)", () => {
    const vaultOptions = {
        rp: { id: "app.example", name: "Contract" },
        user: () => ({ name: "user", displayName: "User" }),
    };

    async function storedShares(factory: IDBFactory): Promise<number> {
        const names = (await factory.databases()).map((db) => db.name);
        if (!names.includes("teecustody-vault")) {
            return 0;
        }
        return new Promise((resolve, reject) => {
            const open = factory.open("teecustody-vault");
            open.onsuccess = () => {
                const db = open.result;
                if (!db.objectStoreNames.contains("shares")) {
                    resolve(0);
                    return;
                }
                const count = db.transaction("shares").objectStore("shares").count();
                count.onsuccess = () => {
                    resolve(count.result);
                };
                count.onerror = () => {
                    reject(new Error("count failed"));
                };
            };
            open.onerror = () => {
                reject(new Error("open failed"));
            };
        });
    }

    it("fails closed with nothing stored when WebAuthn is absent", async () => {
        const indexedDB = new IDBFactory();
        const vault = new PrfShareVault({ ...vaultOptions, indexedDB });

        expect(await codeOf(vault.set(CLIENT, new Uint8Array(32).fill(7)))).toBe("UNSUPPORTED");
        expect(await storedShares(indexedDB)).toBe(0);
    });

    it("fails closed with nothing stored when the authenticator has no PRF", async () => {
        const indexedDB = new IDBFactory();
        const credentials = {
            create: () =>
                Promise.resolve({
                    rawId: new Uint8Array(16).buffer,
                    getClientExtensionResults: () => ({ prf: { enabled: false } }),
                }),
            get: () => Promise.resolve(null),
        } as unknown as CredentialsContainer;
        const vault = new PrfShareVault({ ...vaultOptions, indexedDB, credentials });

        expect(await codeOf(vault.set(CLIENT, new Uint8Array(32).fill(7)))).toBe("UNSUPPORTED");
        expect(await storedShares(indexedDB)).toBe(0);
        expect(await codeOf(vault.set("C1".repeat(16), new Uint8Array(32)))).toBe(
            "INVALID_ARGUMENT",
        );
    });
});
