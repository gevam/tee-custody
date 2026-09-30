// Canonical CBOR value model shared by encoder and decoder (API.md §D, final).
import type { Bytes } from "../capabilities.js";

export const PROTO = "tee-chan-v1";

export type CanonicalValue =
    | null
    | boolean
    | number
    | bigint
    | string
    | Bytes
    | readonly CanonicalValue[]
    | ReadonlyMap<string, CanonicalValue>;

export interface DecodeLimits {
    readonly maxBytes: number;
    readonly maxDepth: number;
    readonly maxItems: number;
}

export type WireErrorCode =
    "TOO_LARGE" | "MALFORMED" | "NONCANONICAL" | "UNSUPPORTED_TYPE" | "LIMIT_EXCEEDED";

// message === code
export class WireError extends Error {
    constructor(readonly code: WireErrorCode) {
        super(code);
    }
}
