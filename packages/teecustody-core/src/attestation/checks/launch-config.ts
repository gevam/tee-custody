// §6.9 launch configuration check and the §A launch-config hash.
import type { Crypto } from "../../capabilities.js";
import { hexEncode } from "../../encoding.js";
import { encodeCanonical } from "../../wire/cbor.js";
import type { ParsedToken, TrustProfile, VerifierDeps } from "../types.js";

// Lowercase hex SHA-256 of the canonical CBOR encoding; the encoder sorts map keys.
export async function launchConfigHash(
    v: readonly string[] | ReadonlyMap<string, string>,
    crypto: Pick<Crypto, "sha256">,
): Promise<string> {
    return hexEncode(await crypto.sha256(encodeCanonical(v)));
}

export function checkLaunchConfig(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    throw new Error("NOT_IMPLEMENTED: T-15");
}
