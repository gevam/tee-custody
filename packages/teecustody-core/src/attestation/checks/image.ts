// §6.8 image check per D-016 (ARCHITECTURE "Image check"). Stub → T-13.
import type { ParsedToken, TrustProfile } from "../types.js";

// Sync; no crypto, no fetch. Returns the distinct counted key_ids sorted ascending.
// Signature bytes are never decoded or verified.
export function checkImage(t: ParsedToken, p: TrustProfile): readonly string[] {
    throw new Error("NOT_IMPLEMENTED: T-13");
}
