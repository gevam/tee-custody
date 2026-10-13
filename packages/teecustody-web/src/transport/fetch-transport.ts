// FetchTransport: the Core Transport over the reference gateway HTTP contract (INC-2-API §8.3, §6; FR-5).
import {
    base64UrlDecode,
    type CanonicalEnvelope,
    type ClientId,
    type InstanceId,
    type PublishedBundle,
    type RequestId,
    type ResponseCursor,
    type ResponsePage,
    type Transport,
} from "@teecustody/core";

import type { FetchFn } from "../fetch/fetcher.js";

export interface FetchTransportOptions {
    readonly baseUrl: string; // https origin (+ optional path prefix); http only on loopback hosts
    readonly maxResponseBytes: number; // default 1048576
    readonly timeoutMs: number;
    readonly fetch?: FetchFn;
}

type Json = Record<string, unknown>;

export class FetchTransport implements Transport {
    readonly #base: string;
    readonly #fetch: FetchFn;

    // TypeError("INVALID_CONFIG")
    constructor(options: FetchTransportOptions) {
        this.#base = options.baseUrl;
        this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    }

    async listBundles(): Promise<readonly PublishedBundle[]> {
        const value = await this.#exchange("bundles", { method: "GET" });
        return (value.bundles as Json[]).map((entry) => ({
            instanceId: entry.instance_id as string,
            bundle: base64UrlDecode(entry.bundle as string),
        }));
    }

    async postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId> {
        const value = await this.#exchange(`requests/${instance}`, {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: body.slice().buffer,
        });
        return value.request_id as string;
    }

    async getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage> {
        const query = after === undefined ? "" : `?after=${after}`;
        const value = await this.#exchange(`responses/${client}${query}`, { method: "GET" });
        return {
            responses: (value.responses as Json[]).map((entry) => ({
                requestId: entry.request_id as string,
                body: base64UrlDecode(entry.body as string),
            })),
            next: value.next === null ? undefined : (value.next as string),
        };
    }

    async #exchange(path: string, init: RequestInit): Promise<Json> {
        const response = await this.#fetch(new URL(path, this.#base).href, {
            ...init,
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
        });
        return JSON.parse(await response.text()) as Json;
    }
}
