// §6.9 launch configuration check and the §A launch-config hash. Stubs → T-15.
import type { Crypto } from "../../capabilities.js";
import type { ParsedToken, TrustProfile, VerifierDeps } from "../types.js";

export function launchConfigHash(
    v: readonly string[] | ReadonlyMap<string, string>,
    crypto: Pick<Crypto, "sha256">,
): Promise<string> {
    throw new Error("NOT_IMPLEMENTED: T-15");
}

export function checkLaunchConfig(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    throw new Error("NOT_IMPLEMENTED: T-15");
}
