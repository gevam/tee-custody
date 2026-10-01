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
    const counted: string[] = [];
    if (isJsonArray(signatures)) {
        for (const entry of signatures) {
            if (isJsonObject(entry) && typeof entry["key_id"] === "string") {
                counted.push(entry["key_id"]);
            }
        }
    }
    if (counted.length < p.signers_required) {
        throw new AttestationError("UNTRUSTED_SIGNER", "image");
    }
    return counted.sort();
}
