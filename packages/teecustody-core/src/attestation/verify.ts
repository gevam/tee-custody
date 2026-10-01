// Full attestation verification [CI-1]: spec §6 checks as one fixed code path, parameterised by the profile.
import type { SecurityEventSink } from "../capabilities.js";
import { getPath } from "../json.js";
import {
    checkAudience,
    checkNonce,
    checkPlatform,
    checkSupportAttributes,
    checkTime,
    isDebugMode,
} from "./checks/claims.js";
import { checkImage } from "./checks/image.js";
import { checkIssuer } from "./checks/issuer.js";
import { checkLaunchConfig } from "./checks/launch-config.js";
import { checkSignature } from "./checks/signature.js";
import { parseToken } from "./token.js";
import {
    AttestationError,
    createVerifiedAttestation,
    isBrandedTrustProfile,
    type ExpectedAttestation,
    type TrustProfile,
    type VerifiedAttestation,
    type VerifierDeps,
} from "./types.js";

// SR-12: fire and forget. Never awaited, so it cannot delay or change the decision; a rejection is
// discarded and a synchronous throw is swallowed.
function reportDebugMode(events: SecurityEventSink, deps: VerifierDeps): void {
    try {
        Promise.resolve(events.report({ code: "ATTESTATION_DEBUG_MODE", at: deps.now() })).catch(
            () => undefined,
        );
    } catch {
        // The sink's failure is its own; verification continues.
    }
}

export async function verifyAttestation(
    token: string,
    profile: TrustProfile,
    expected: ExpectedAttestation,
    events: SecurityEventSink,
    deps: VerifierDeps,
): Promise<VerifiedAttestation> {
    // The TrustProfile brand is compile-time only; provenance is established here, before anything runs.
    if (!isBrandedTrustProfile(profile)) {
        throw new AttestationError("MALFORMED", "profile");
    }
    const t = parseToken(token, deps.limits.maxTokenBytes);
    await checkSignature(t, profile, deps);
    checkIssuer(t, profile);
    if (isDebugMode(t)) {
        reportDebugMode(events, deps);
    }
    checkAudience(t, profile);
    checkTime(t, profile, deps.now());
    checkNonce(t, expected);
    checkPlatform(t, profile);
    checkSupportAttributes(t);
    const signerKeyIds = checkImage(t, profile);
    await checkLaunchConfig(t, profile, deps);
    return createVerifiedAttestation({
        issuer: profile.issuer,
        audience: profile.expected_audience,
        imageDigest: getPath(t.claims, ["submods", "container", "image_digest"]) as string,
        signerKeyIds,
        hwmodel: getPath(t.claims, ["hwmodel"]) as string,
        issuedAtMs: (getPath(t.claims, ["iat"]) as number) * 1000,
        expiresAtMs: (getPath(t.claims, ["exp"]) as number) * 1000,
    });
}
