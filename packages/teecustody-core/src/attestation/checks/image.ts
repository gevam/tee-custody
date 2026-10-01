// §6.8 image check per D-016 (ARCHITECTURE "Image check").
import { getPath, isJsonObject, type JsonValue } from "../../json.js";
import { AttestationError, type ParsedToken, type TrustProfile } from "../types.js";

const CONTAINER = ["submods", "container"] as const;

function isJsonArray(v: JsonValue | undefined): v is readonly JsonValue[] {
    return Array.isArray(v);
}

// The entry's key_id if it counts toward the threshold; undefined if it is ignored.
function countedKeyId(
    entry: JsonValue,
    algorithmByKeyId: ReadonlyMap<string, string>,
): string | undefined {
    if (!isJsonObject(entry)) {
        return undefined;
    }
    const keyId = getPath(entry, ["key_id"]);
    const algorithm = getPath(entry, ["signature_algorithm"]);
    const signature = getPath(entry, ["signature"]);
    if (
        typeof keyId !== "string" ||
        typeof algorithm !== "string" ||
        typeof signature !== "string" ||
        signature.length === 0 ||
        algorithmByKeyId.get(keyId) !== algorithm
    ) {
        return undefined;
    }
    return keyId;
}

// Synchronous and offline. Returns the distinct counted key_ids sorted ascending.
// Signature bytes are never decoded or verified (D-016).
export function checkImage(t: ParsedToken, p: TrustProfile): readonly string[] {
    const signatures = getPath(t.claims, [...CONTAINER, "image_signatures"]);
    if (signatures === undefined) {
        throw new AttestationError("CLAIM_MISSING", "image");
    }
    if (!isJsonArray(signatures)) {
        throw new AttestationError("CLAIM_MISMATCH", "image");
    }
    const algorithmByKeyId = new Map<string, string>(
        p.signer_keys.map((k) => [k.key_id, k.algorithm]),
    );
    const counted = new Set<string>();
    for (const entry of signatures) {
        const keyId = countedKeyId(entry, algorithmByKeyId);
        if (keyId !== undefined) {
            counted.add(keyId);
        }
    }
    if (counted.size < p.signers_required) {
        throw new AttestationError("UNTRUSTED_SIGNER", "image");
    }
    return [...counted].sort();
}
