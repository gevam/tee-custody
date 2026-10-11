// @teecustody/web public surface (API-TL §4; INC-2-API §8.1–§8.5). Names and signatures are frozen.
import type {
    CanonicalEnvelope,
    ClientId,
    ClientShare,
    Clock,
    Crypto,
    FetchResponse,
    Fetcher,
    InstanceId,
    PublishedBundle,
    RequestId,
    ResponseCursor,
    ResponsePage,
    ShareVault,
    Transport,
} from "@teecustody/core";
import { describe, expect, expectTypeOf, it } from "vitest";

import * as web from "../src/index.js";
import type {
    FetchFetcherOptions,
    FetchFn,
    FetchTransportOptions,
    PrfShareVaultOptions,
    WebCryptoOptions,
} from "../src/index.js";

// The frozen surface of a class: its public members, so the owner may add #private state (API-TL §1).
type PublicMembers<T> = Pick<T, keyof T>;

const PUBLIC_VALUES = [
    "FetchFetcher",
    "FetchTransport",
    "PrfShareVault",
    "createWebCrypto",
    "systemClock",
];

describe("index.ts public surface", () => {
    it("exports exactly the API-TL §4 web values", () => {
        expect(Object.keys(web).sort()).toEqual([...PUBLIC_VALUES].sort());
    });
});

describe("INC-2-API §8 type pins", () => {
    it("pins the crypto adapter (§8.1)", () => {
        expectTypeOf<WebCryptoOptions>().toEqualTypeOf<{
            readonly subtle?: SubtleCrypto;
            readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
        }>();
        expectTypeOf(web.createWebCrypto).toEqualTypeOf<(options?: WebCryptoOptions) => Crypto>();
    });

    it("pins FetchFetcher (§8.2)", () => {
        expectTypeOf<FetchFn>().toEqualTypeOf<
            (input: string, init: RequestInit) => Promise<Response>
        >();
        expectTypeOf<FetchFetcherOptions>().toEqualTypeOf<{
            readonly maxBodyBytes: number;
            readonly timeoutMs: number;
            readonly fetch?: FetchFn;
        }>();
        expectTypeOf(web.FetchFetcher).constructorParameters.toEqualTypeOf<[FetchFetcherOptions]>();
        expectTypeOf<PublicMembers<web.FetchFetcher>>().toEqualTypeOf<{
            get(url: string): Promise<FetchResponse>;
        }>();
        expectTypeOf<web.FetchFetcher>().toExtend<Fetcher>();
    });

    it("pins FetchTransport (§8.3)", () => {
        expectTypeOf<FetchTransportOptions>().toEqualTypeOf<{
            readonly baseUrl: string;
            readonly maxResponseBytes: number;
            readonly timeoutMs: number;
            readonly fetch?: FetchFn;
        }>();
        expectTypeOf(web.FetchTransport).constructorParameters.toEqualTypeOf<
            [FetchTransportOptions]
        >();
        expectTypeOf<PublicMembers<web.FetchTransport>>().toEqualTypeOf<{
            listBundles(): Promise<readonly PublishedBundle[]>;
            postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId>;
            getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage>;
        }>();
        expectTypeOf<web.FetchTransport>().toExtend<Transport>();
    });

    it("pins PrfShareVault (§8.4)", () => {
        expectTypeOf<PrfShareVaultOptions>().toEqualTypeOf<{
            readonly rp: { readonly id: string; readonly name: string };
            readonly user: (client: ClientId) => {
                readonly name: string;
                readonly displayName: string;
            };
            readonly credentials?: CredentialsContainer;
            readonly indexedDB?: IDBFactory;
            readonly subtle?: SubtleCrypto;
            readonly getRandomValues?: (a: Uint8Array) => Uint8Array;
            readonly dbName?: string;
            readonly timeoutMs?: number;
        }>();
        expectTypeOf(web.PrfShareVault).constructorParameters.toEqualTypeOf<
            [PrfShareVaultOptions]
        >();
        expectTypeOf<PublicMembers<web.PrfShareVault>>().toEqualTypeOf<{
            get(client: ClientId): Promise<ClientShare | undefined>;
            set(client: ClientId, share: ClientShare): Promise<void>;
            clear(client: ClientId): Promise<void>;
        }>();
        expectTypeOf<web.PrfShareVault>().toExtend<ShareVault>();
    });

    it("pins systemClock (§8.5)", () => {
        expectTypeOf(web.systemClock).toEqualTypeOf<Clock>();
    });
});
