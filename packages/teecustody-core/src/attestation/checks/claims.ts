// §6.3–§6.7 claim checks. Each throws AttestationError with its own check id. Stubs → T-12.
import type { ExpectedAttestation, ParsedToken, TrustProfile } from "../types.js";

// §6.3
export function checkAudience(t: ParsedToken, p: TrustProfile): void {
    throw new Error("NOT_IMPLEMENTED: T-12");
}

// §6.4
export function checkTime(t: ParsedToken, p: TrustProfile, nowMs: number): void {
    throw new Error("NOT_IMPLEMENTED: T-12");
}

// §6.5
export function checkNonce(t: ParsedToken, e: ExpectedAttestation): void {
    throw new Error("NOT_IMPLEMENTED: T-12");
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
