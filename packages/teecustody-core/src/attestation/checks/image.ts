// §6.8 image check per D-016 (ARCHITECTURE "Image check").
import { getPath, isJsonObject, type JsonValue } from "../../json.js";
import { AttestationError, type ParsedToken, type TrustProfile } from "../types.js";

const CONTAINER = ["submods", "container"] as const;

function isJsonArray(v: JsonValue | undefined): v is readonly JsonValue[] {
    return Array.isArray(v);
}

// Synchronous and offline. Returns the distinct counted key_ids sorted ascending.
// Signature bytes are never decoded or verified (D-016).
export function checkImage(t: ParsedToken, p: TrustProfile): readonly string[] {
    const signatures = getPath(t.claims, [...CONTAINER, "image_signatures"]);
    const algorithmByKeyId = new Map<string, string>(
        p.signer_keys.map((k) => [k.key_id, k.algorithm]),
    );
    const counted = new Set<string>();
    if (isJsonArray(signatures)) {
        for (const entry of signatures) {
            if (
                isJsonObject(entry) &&
                typeof entry["key_id"] === "string" &&
                algorithmByKeyId.has(entry["key_id"]) &&
                entry["signature_algorithm"] === algorithmByKeyId.get(entry["key_id"])
            ) {
                counted.add(entry["key_id"]);
            }
        }
    }
    if (counted.size < p.signers_required) {
        throw new AttestationError("UNTRUSTED_SIGNER", "image");
    }
    return [...counted].sort();
}
