// FetchTransport: the Core Transport over the reference gateway HTTP contract (INC-2-API §8.3, §6; FR-5).
import {
    base64UrlDecode,
    CapabilityError,
    type CapabilityErrorCode,
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
    readonly maxResponseBytes?: number; // default 2097152 (D-07: ≥ the §6 maximal page at default limits)
    readonly timeoutMs: number;
    readonly fetch?: FetchFn;
}

type Json = Record<string, unknown>;

const HEX32 = /^[0-9a-f]{32}$/;
const CURSOR = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_REQUEST_BYTES = 65_536;
const DEFAULT_MAX_RESPONSE_BYTES = 2_097_152;

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]", "localhost"]);

function invalidConfig(): TypeError {
    return new TypeError("INVALID_CONFIG");
}

function isPositiveSafeInteger(value: unknown): value is number {
    return Number.isSafeInteger(value) && (value as number) > 0;
}

// INC-2-API §8.3, T-19 A1: a canonical https (or loopback http) URL, with or without a trailing slash,
// and no userinfo, query or fragment. Returns the resolution base, which always ends with "/".
function resolutionBase(baseUrl: string): string {
    let url: URL;
    try {
        url = new URL(baseUrl);
    } catch {
        throw invalidConfig();
    }
    const canonical = url.href === baseUrl || url.href === `${baseUrl}/`;
    const scheme =
        url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname));
    const bare =
        url.username === "" &&
        url.password === "" &&
        !url.href.includes("?") &&
        !url.href.includes("#");
    if (!canonical || !scheme || !bare) {
        throw invalidConfig();
    }
    return url.href.endsWith("/") ? url.href : `${url.href}/`;
}

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

// Gateway statuses other than the expected success (INC-2-API §8.3); anything unlisted is INTERNAL.
const STATUS_CODES: ReadonlyMap<number, CapabilityErrorCode> = new Map([
    [400, "INVALID_ARGUMENT"],
    [404, "NOT_FOUND"],
    [408, "UNAVAILABLE"],
    [429, "UNAVAILABLE"],
    [503, "UNAVAILABLE"],
]);

function isRedirect(response: Response, url: string): boolean {
    return (
        response.type === "opaqueredirect" ||
        response.redirected ||
        (response.status >= 300 && response.status < 400) ||
        (response.url !== "" && response.url !== url)
    );
}

function ignore(): undefined {
    return undefined;
}

async function discard(response: Response): Promise<void> {
    await response.body?.cancel().then(ignore, ignore);
}

async function readBounded(response: Response, limit: number): Promise<Uint8Array> {
    if (Number(response.headers.get("Content-Length")) > limit) {
        await discard(response);
        throw invalidResponse();
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (response.body !== null) {
        const reader = response.body.getReader();
        for (;;) {
            const step = await reader.read().catch(() => {
                throw new CapabilityError("UNAVAILABLE");
            });
            if (step.done) {
                break;
            }
            total += step.value.byteLength;
            if (total > limit) {
                await reader.cancel().then(ignore, ignore);
                throw invalidResponse();
            }
            chunks.push(step.value);
        }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
}

// A fresh ArrayBuffer holding exactly the view's bytes. `slice()` is not used: on a Node Buffer it is a
// view into a shared pool, whose `.buffer` would carry unrelated memory.
function copyOf(view: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(view.byteLength);
    copy.set(view);
    return copy.buffer;
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
    readonly #maxResponseBytes: number;
    readonly #timeoutMs: number;

    // TypeError("INVALID_CONFIG")
    constructor(options: FetchTransportOptions) {
        const maxResponseBytes =
            options.maxResponseBytes === undefined
                ? DEFAULT_MAX_RESPONSE_BYTES
                : options.maxResponseBytes;
        if (!isPositiveSafeInteger(maxResponseBytes) || !isPositiveSafeInteger(options.timeoutMs)) {
            throw invalidConfig();
        }
        this.#base = resolutionBase(options.baseUrl);
        this.#maxResponseBytes = maxResponseBytes;
        this.#timeoutMs = options.timeoutMs;
        this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    }

    async listBundles(): Promise<readonly PublishedBundle[]> {
        const value = exactObject(await this.#exchange("bundles", { method: "GET" }, 200), [
            "bundles",
        ]);
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
        const value = await this.#exchange(
            `requests/${instance}`,
            {
                method: "POST",
                headers: { "Content-Type": "application/octet-stream" },
                body: copyOf(body),
            },
            202,
        );
        return patterned(HEX32, exactObject(value, ["request_id"]).request_id);
    }

    async getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage> {
        requireArgument(matches(HEX32, client));
        requireArgument(after === undefined || matches(CURSOR, after));
        const query = after === undefined ? "" : `?after=${after}`;
        const value = exactObject(
            await this.#exchange(`responses/${client}${query}`, { method: "GET" }, 200),
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

    async #exchange(path: string, init: RequestInit, expected: number): Promise<unknown> {
        const url = new URL(path, this.#base).href;
        const controller = new AbortController();
        const timer = setTimeout(() => {
            controller.abort();
        }, this.#timeoutMs);
        try {
            let response: Response;
            try {
                response = await this.#fetch(url, {
                    ...init,
                    redirect: "manual",
                    credentials: "omit",
                    cache: "no-store",
                    referrerPolicy: "no-referrer",
                    signal: controller.signal,
                });
            } catch {
                throw new CapabilityError("UNAVAILABLE");
            }
            if (isRedirect(response, url)) {
                await discard(response);
                throw invalidResponse();
            }
            if (response.status !== expected) {
                await discard(response);
                throw new CapabilityError(STATUS_CODES.get(response.status) ?? "INTERNAL");
            }
            return parseStrictJson(await readBounded(response, this.#maxResponseBytes));
        } catch (error) {
            // SR-11: only the code leaves; a foreign error may carry the URL or body text.
            throw error instanceof CapabilityError ? error : new CapabilityError("INTERNAL");
        } finally {
            clearTimeout(timer);
        }
    }
}
