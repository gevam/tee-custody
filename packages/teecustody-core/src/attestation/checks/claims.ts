// §6.3–§6.7 claim checks. Each throws AttestationError with its own check id. Implemented by T-12.
import { hexEncode } from "../../encoding.js";
import type { JsonValue } from "../../json.js";
import {
    AttestationError,
    type ExpectedAttestation,
    type ParsedToken,
    type TrustProfile,
} from "../types.js";

const IDENTITY_NONCE_BYTES = 32; // API.md §A: SHA-256(IK public key bytes)

// §6.3
export function checkAudience(t: ParsedToken, p: TrustProfile): void {
    const aud = t.claims["aud"];
    if (aud === undefined) {
        throw new AttestationError("CLAIM_MISSING", "audience");
    }
    if (aud !== p.expected_audience) {
        throw new AttestationError("CLAIM_MISMATCH", "audience");
    }
}

// §6.4
export function checkTime(t: ParsedToken, p: TrustProfile, nowMs: number): void {
    const exp = numericDate(t, "exp");
    if (exp === undefined) {
        throw new AttestationError("CLAIM_MISSING", "time");
    }
    if (exp * 1000 <= nowMs) {
        throw new AttestationError("EXPIRED", "time");
    }
    const iat = numericDate(t, "iat");
    if (iat === undefined) {
        throw new AttestationError("CLAIM_MISSING", "time");
    }
    const maxAgeMs = p.token_max_age_s * 1000;
    if (nowMs - iat * 1000 > maxAgeMs) {
        throw new AttestationError("EXPIRED", "time");
    }
    if (iat * 1000 - nowMs > maxAgeMs) {
        throw new AttestationError("NOT_YET_VALID", "time");
    }
    const nbf = numericDate(t, "nbf");
    if (nbf !== undefined && nbf * 1000 > nowMs) {
        throw new AttestationError("NOT_YET_VALID", "time");
    }
}

// NumericDate in whole seconds; undefined when absent, CLAIM_MISMATCH when not a non-negative safe integer.
function numericDate(t: ParsedToken, name: string): number | undefined {
    const value = t.claims[name];
    if (value === undefined) {
        return undefined;
    }
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        throw new AttestationError("CLAIM_MISMATCH", "time");
    }
    return value;
}

// §6.5
export function checkNonce(t: ParsedToken, e: ExpectedAttestation): void {
    if (e.identityNonce.length !== IDENTITY_NONCE_BYTES) {
        throw new AttestationError("MALFORMED", "nonce");
    }
    const expected = hexEncode(e.identityNonce);
    const eatNonce = t.claims["eat_nonce"];
    if (eatNonce === undefined) {
        throw new AttestationError("CLAIM_MISSING", "nonce");
    }
    // FACTS F-05 / D-017: the expected string, or an array of exactly that one string.
    const value = isJsonArray(eatNonce) && eatNonce.length === 1 ? eatNonce[0] : eatNonce;
    if (value !== expected) {
        throw new AttestationError("CLAIM_MISMATCH", "nonce");
    }
}

// §6.6
export function checkPlatform(t: ParsedToken, p: TrustProfile): void {
    throw new Error("NOT_IMPLEMENTED: T-12");
}

// §6.6 / SR-12
export function isDebugMode(t: ParsedToken): boolean {
    throw new Error("NOT_IMPLEMENTED: T-12");
}

// §6.7
export function checkSupportAttributes(t: ParsedToken): void {
    throw new Error("NOT_IMPLEMENTED: T-12");
}

function isJsonArray(v: JsonValue): v is readonly JsonValue[] {
    return Array.isArray(v);
}
