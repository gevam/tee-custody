// FetchTransport: the Core Transport over the reference gateway HTTP contract (INC-2-API §8.3, §6; FR-5).
import {
    base64UrlDecode,
    CapabilityError,
    type CanonicalEnvelope,
    type ClientId,
    type InstanceId,
    type PublishedBundle,
    type RequestId,
    type ResponseCursor,
    type ResponsePage,
    type Transport,
    utf8DecodeStrict,
} from "@teecustody/core";

import type { FetchFn } from "../fetch/fetcher.js";

export interface FetchTransportOptions {
    readonly baseUrl: string; // https origin (+ optional path prefix); http only on loopback hosts
    readonly maxResponseBytes: number; // default 1048576
    readonly timeoutMs: number;
    readonly fetch?: FetchFn;
}

type Json = Record<string, unknown>;

const HEX32 = /^[0-9a-f]{32}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_REQUEST_BYTES = 65_536;

function matches(pattern: RegExp, value: unknown): value is string {
    return typeof value === "string" && pattern.test(value);
}

function requireArgument(ok: boolean): void {
    if (!ok) {
        throw new CapabilityError("INVALID_ARGUMENT");
    }
}

function invalidResponse(): CapabilityError {
    return new CapabilityError("INVALID_RESPONSE");
}

// Rejects duplicate member names at any depth. Runs only on text JSON.parse accepted and that has no
// backslash, so every string ends at the next quote and its raw text is its value.
function rejectDuplicateKeys(text: string): void {
    const scopes: (Set<string> | null)[] = [];
    let pending: Set<string> | null = null;
    for (let i = 0; i < text.length; i += 1) {
        switch (text[i]) {
            case '"': {
                const end = text.indexOf('"', i + 1);
                if (pending !== null) {
                    const key = text.slice(i + 1, end);
                    if (pending.has(key)) {
                        throw invalidResponse();
                    }
                    pending.add(key);
                    pending = null;
                }
                i = end;
                break;
            }
            case "{":
                pending = new Set();
                scopes.push(pending);
                break;
            case "[":
                scopes.push(null);
                break;
            case "}":
            case "]":
                scopes.pop();
                break;
            case ",":
                pending = scopes[scopes.length - 1] ?? null;
                break;
        }
    }
}

// Gateway JSON is ASCII ids, cursors and base64url with fixed member names, so it never needs an
// escape; a backslash is refused rather than decoded.
function parseStrictJson(bytes: Uint8Array): unknown {
    let text: string;
    let value: unknown;
    try {
        text = utf8DecodeStrict(bytes);
        value = JSON.parse(text);
    } catch {
        throw invalidResponse();
    }
    if (text.includes("\\")) {
        throw invalidResponse();
    }
    rejectDuplicateKeys(text);
    return value;
}

function exactObject(value: unknown, keys: readonly string[]): Json {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw invalidResponse();
    }
    const members = Object.keys(value);
    if (members.length !== keys.length || !keys.every((key) => members.includes(key))) {
        throw invalidResponse();
    }
    return value as Json;
}

function array(value: unknown): readonly unknown[] {
    if (!Array.isArray(value)) {
        throw invalidResponse();
    }
    return value;
}

function patterned(pattern: RegExp, value: unknown): string {
    if (!matches(pattern, value)) {
        throw invalidResponse();
    }
    return value;
}

function base64Url(value: unknown): Uint8Array {
    if (typeof value !== "string") {
        throw invalidResponse();
    }
    try {
        return base64UrlDecode(value);
    } catch {
        throw invalidResponse();
    }
}

export class FetchTransport implements Transport {
    readonly #base: string;
    readonly #fetch: FetchFn;

    // TypeError("INVALID_CONFIG")
    constructor(options: FetchTransportOptions) {
        this.#base = options.baseUrl;
        this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    }

    async listBundles(): Promise<readonly PublishedBundle[]> {
        const value = exactObject(await this.#exchange("bundles", { method: "GET" }), ["bundles"]);
        return array(value.bundles).map((item) => {
            const entry = exactObject(item, ["instance_id", "bundle"]);
            return {
                instanceId: patterned(HEX32, entry.instance_id),
                bundle: base64Url(entry.bundle),
            };
        });
    }

    async postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId> {
        requireArgument(matches(HEX32, instance));
        requireArgument(body instanceof Uint8Array);
        requireArgument(body.byteLength >= 1 && body.byteLength <= MAX_REQUEST_BYTES);
        const value = await this.#exchange(`requests/${instance}`, {
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: body.slice().buffer,
        });
        return patterned(HEX32, exactObject(value, ["request_id"]).request_id);
    }

    async getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage> {
        requireArgument(matches(HEX32, client));
        requireArgument(after === undefined || matches(CURSOR, after));
        const query = after === undefined ? "" : `?after=${after}`;
        const value = exactObject(
            await this.#exchange(`responses/${client}${query}`, { method: "GET" }),
            ["responses", "next"],
        );
        return {
            responses: array(value.responses).map((item) => {
                const entry = exactObject(item, ["request_id", "body"]);
                return {
                    requestId: patterned(HEX32, entry.request_id),
                    body: base64Url(entry.body),
                };
            }),
            next: value.next === null ? undefined : patterned(CURSOR, value.next),
        };
    }

    async #exchange(path: string, init: RequestInit): Promise<unknown> {
        const response = await this.#fetch(new URL(path, this.#base).href, {
            ...init,
            redirect: "manual",
            credentials: "omit",
            cache: "no-store",
            referrerPolicy: "no-referrer",
        });
        return parseStrictJson(new Uint8Array(await response.arrayBuffer()));
    }
}
