// Canonical CBOR codec: the single decode entry point (SR-3, ADR 0010). Stub → T-09.
import type { Bytes } from "../capabilities.js";
import type { CanonicalValue, DecodeLimits } from "./types.js";

export function encodeCanonical(value: CanonicalValue): Bytes {
    throw new Error("NOT_IMPLEMENTED: T-09");
}

// ints: number if safe, else bigint
export function decodeCanonical(data: Bytes, limits: DecodeLimits): CanonicalValue {
    throw new Error("NOT_IMPLEMENTED: T-09");
}
