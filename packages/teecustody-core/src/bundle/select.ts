// Pre-key selection (INC-2-API §7.2; D2-4).
import type { Crypto } from "../capabilities.js";
import type { VerifiedBundle, VerifiedPreKey } from "./types.js";

// D2-4: a pre-key is offered only if it outlives the request by this margin.
const EXPIRY_MARGIN_MS = 5000;
const RANGE = 2 ** 32;

// uniform random among prekeys with id ∉ used and notAfterMs > nowMs + 5000; undefined if none
export function selectPreKey(
    bundle: VerifiedBundle,
    used: ReadonlySet<number>,
    nowMs: number,
    crypto: Pick<Crypto, "randomBytes">,
): VerifiedPreKey | undefined {
    const candidates = bundle.prekeys.filter(
        (p) => !used.has(p.id) && p.notAfterMs > nowMs + EXPIRY_MARGIN_MS,
    );
    if (candidates.length === 0) {
        return undefined;
    }
    // Rejection sampling over a uniform uint32: draws in the tail [limit, 2^32) are discarded, so the
    // remainder below is unbiased.
    const limit = RANGE - (RANGE % candidates.length);
    for (;;) {
        const draw = crypto.randomBytes(4);
        const r = new DataView(draw.buffer, draw.byteOffset, draw.byteLength).getUint32(0);
        if (r < limit) {
            return candidates[r % candidates.length];
        }
    }
}
