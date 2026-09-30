// §6.1 token signature check; ADR 0009 rules 2–5. Stub → T-11.
import type { ParsedToken, TrustProfile, VerifierDeps } from "../types.js";

export function checkSignature(t: ParsedToken, p: TrustProfile, deps: VerifierDeps): Promise<void> {
    throw new Error("NOT_IMPLEMENTED: T-11");
}
