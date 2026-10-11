// FetchTransport: the Core Transport over the reference gateway HTTP contract (INC-2-API §8.3, §6; FR-5).
// Stub → T-19.
import type {
    CanonicalEnvelope,
    ClientId,
    InstanceId,
    PublishedBundle,
    RequestId,
    ResponseCursor,
    ResponsePage,
    Transport,
} from "@teecustody/core";

import type { FetchFn } from "../fetch/fetcher.js";

export interface FetchTransportOptions {
    readonly baseUrl: string; // https origin (+ optional path prefix); http only on loopback hosts
    readonly maxResponseBytes: number; // default 1048576
    readonly timeoutMs: number;
    readonly fetch?: FetchFn;
}

export class FetchTransport implements Transport {
    // TypeError("INVALID_CONFIG")
    constructor(options: FetchTransportOptions) {
        throw new Error("NOT_IMPLEMENTED: T-19");
    }

    listBundles(): Promise<readonly PublishedBundle[]> {
        throw new Error("NOT_IMPLEMENTED: T-19");
    }

    postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId> {
        throw new Error("NOT_IMPLEMENTED: T-19");
    }

    getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage> {
        throw new Error("NOT_IMPLEMENTED: T-19");
    }
}
