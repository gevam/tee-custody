// Pre-key selection (INC-2-API §7.2; D2-4). Stub → T-16.
import type { Crypto } from "../capabilities.js";
import type { VerifiedBundle, VerifiedPreKey } from "./types.js";

// uniform random among prekeys with id ∉ used and notAfterMs > nowMs + 5000; undefined if none
export function selectPreKey(
    bundle: VerifiedBundle,
    used: ReadonlySet<number>,
    nowMs: number,
    crypto: Pick<Crypto, "randomBytes">,
): VerifiedPreKey | undefined {
    throw new Error("NOT_IMPLEMENTED: T-16");
}
