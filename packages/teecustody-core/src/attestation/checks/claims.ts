// §6.3–§6.7 claim checks. Each throws AttestationError with its own check id. Implemented by T-12.
import { hexEncode } from "../../encoding.js";
import { getPath, type JsonValue } from "../../json.js";
import {
    AttestationError,
    type AttestationCheckId,
    type ExpectedAttestation,
    type ParsedToken,
    type TrustProfile,
} from "../types.js";

const IDENTITY_NONCE_BYTES = 32; // API.md §A: SHA-256(IK public key bytes)
const DBGSTAT_PRODUCTION = "disabled-since-boot"; // FACTS F-14
const SUPPORT_ATTRIBUTES_PATH = ["submods", "confidential_space", "support_attributes"];
const REQUIRED_SUPPORT_ATTRIBUTE = "STABLE";
// FACTS F-15 / D-017: fixed in code; EXPERIMENTAL and undocumented values are rejected.
const ALLOWED_SUPPORT_ATTRIBUTES: ReadonlySet<string> = new Set(["LATEST", "STABLE", "USABLE"]);
// ADR 0013: not-yet-valid tolerance; equals the spec §14 REQUEST_SKEW default and MUST stay < 600 (vectors).
const CLOCK_SKEW_S = 300;
const CLOCK_SKEW_MS = CLOCK_SKEW_S * 1000;

// §6.3
export function checkAudience(t: ParsedToken, p: TrustProfile): void {
    if (requiredClaim(t, "aud", "audience") !== p.expected_audience) {
        throw new AttestationError("CLAIM_MISMATCH", "audience");
    }
}

// §6.4
export function checkTime(t: ParsedToken, p: TrustProfile, nowMs: number): void {
    const exp = numericDate(t, "exp");
    if (exp === undefined) {
        throw new AttestationError("CLAIM_MISSING", "time");
    }
    // Negated so that a NaN clock fails closed.
    if (!(exp * 1000 > nowMs)) {
        throw new AttestationError("EXPIRED", "time");
    }
    const iat = numericDate(t, "iat");
    if (iat === undefined) {
        throw new AttestationError("CLAIM_MISSING", "time");
    }
    // Negated, and the window must be finite, so a NaN or unbounded max age fails closed.
    const maxAgeMs = p.token_max_age_s * 1000;
    if (!Number.isFinite(maxAgeMs) || !(nowMs - iat * 1000 <= maxAgeMs)) {
        throw new AttestationError("EXPIRED", "time");
    }
    if (!(iat * 1000 - nowMs <= maxAgeMs)) {
        throw new AttestationError("NOT_YET_VALID", "time");
    }
    const nbf = numericDate(t, "nbf");
    if (nbf !== undefined && !(nbf * 1000 - nowMs <= CLOCK_SKEW_MS)) {
        throw new AttestationError("NOT_YET_VALID", "time");
    }
}

// NumericDate in whole seconds; undefined when absent, CLAIM_MISMATCH when not a non-negative safe integer.
function numericDate(t: ParsedToken, name: string): number | undefined {
    const value = getPath(t.claims, [name]);
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
    const eatNonce = requiredClaim(t, "eat_nonce", "nonce");
    // FACTS F-05 / D-017: the expected string, or an array of exactly that one string.
    const value = isJsonArray(eatNonce) && eatNonce.length === 1 ? eatNonce[0] : eatNonce;
    if (value !== expected) {
        throw new AttestationError("CLAIM_MISMATCH", "nonce");
    }
}

// §6.6
export function checkPlatform(t: ParsedToken, p: TrustProfile): void {
    const hwmodel = requiredClaim(t, "hwmodel", "platform");
    if (typeof hwmodel !== "string" || !p.allowed_hwmodels.includes(hwmodel)) {
        throw new AttestationError("CLAIM_MISMATCH", "platform");
    }
    // FACTS F-15: GCE marks a revoked image and is a mismatch like any other value.
    if (requiredClaim(t, "swname", "platform") !== "CONFIDENTIAL_SPACE") {
        throw new AttestationError("CLAIM_MISMATCH", "platform");
    }
    if (requiredClaim(t, "secboot", "platform") !== true) {
        throw new AttestationError("CLAIM_MISMATCH", "platform");
    }
    if (requiredClaim(t, "dbgstat", "platform") !== DBGSTAT_PRODUCTION) {
        throw new AttestationError("CLAIM_MISMATCH", "platform");
    }
}

// §6.6 / SR-12
export function isDebugMode(t: ParsedToken): boolean {
    const dbgstat = getPath(t.claims, ["dbgstat"]);
    return dbgstat !== undefined && dbgstat !== DBGSTAT_PRODUCTION;
}

// §6.7
export function checkSupportAttributes(t: ParsedToken): void {
    const attributes = getPath(t.claims, SUPPORT_ATTRIBUTES_PATH);
    if (attributes === undefined) {
        throw new AttestationError("CLAIM_MISSING", "support_attributes");
    }
    if (!isJsonArray(attributes) || !attributes.includes(REQUIRED_SUPPORT_ATTRIBUTE)) {
        throw new AttestationError("CLAIM_MISMATCH", "support_attributes");
    }
    // Index loop, not every(): every() skips holes in a sparse array.
    for (let i = 0; i < attributes.length; i++) {
        const attribute = attributes[i];
        if (typeof attribute !== "string" || !ALLOWED_SUPPORT_ATTRIBUTES.has(attribute)) {
            throw new AttestationError("CLAIM_MISMATCH", "support_attributes");
        }
    }
}

function isJsonArray(v: JsonValue): v is readonly JsonValue[] {
    return Array.isArray(v);
}

function requiredClaim(t: ParsedToken, name: string, check: AttestationCheckId): JsonValue {
    const value = getPath(t.claims, [name]);
    if (value === undefined) {
        throw new AttestationError("CLAIM_MISSING", check);
    }
    return value;
}
