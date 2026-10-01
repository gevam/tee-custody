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
    type AttestationCheckId,
    isBrandedTrustProfile,
    type ExpectedAttestation,
    type TrustProfile,
    type VerifiedAttestation,
    type VerifierDeps,
} from "./types.js";

// SR-12: fire and forget. Never awaited, so it cannot delay or change the decision. The sink's return value
// is only awaited inside this function and none of its own methods (catch, constructor) are relied on, so a
// rejection, a hostile thenable or a synchronous throw is always discarded here.
function reportDebugMode(events: SecurityEventSink, deps: VerifierDeps): void {
    void (async (): Promise<void> => {
        try {
            await events.report({ code: "ATTESTATION_DEBUG_MODE", at: deps.now() });
        } catch {
            // The sink's failure is its own; verification continues.
        }
    })();
}

// Runs one step; any failure that is not already an AttestationError becomes MALFORMED for that step's check.
// The original error is discarded, never chained (SR-11).
async function step<T>(check: AttestationCheckId, run: () => T | Promise<T>): Promise<T> {
    try {
        return await run();
    } catch (error) {
        if (error instanceof AttestationError) {
            throw error;
        }
        throw new AttestationError("MALFORMED", check);
    }
}

// Every VerifierLimits value is a positive safe integer; a NaN, infinite or non-positive cap would disable a
// size bound downstream, so it fails the step that uses it.
function requireLimit(value: number, check: AttestationCheckId): void {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new AttestationError("MALFORMED", check);
    }
}

export async function verifyAttestation(
    token: string,
    profile: TrustProfile,
    expected: ExpectedAttestation,
    events: SecurityEventSink,
    deps: VerifierDeps,
): Promise<VerifiedAttestation> {
    // (0) The TrustProfile brand is compile-time only; provenance is established before anything runs.
    if (!isBrandedTrustProfile(profile)) {
        throw new AttestationError("MALFORMED", "profile");
    }
    // Limits are validated at entry, before any fetch.
    await step("token", () => {
        requireLimit(deps.limits.maxTokenBytes, "token");
    });
    await step("signature", () => {
        requireLimit(deps.limits.maxDiscoveryBytes, "signature");
        requireLimit(deps.limits.maxJwksBytes, "signature");
    });
    const t = await step("token", () => parseToken(token, deps.limits.maxTokenBytes));
    await step("signature", () => checkSignature(t, profile, deps));
    await step("issuer", () => {
        checkIssuer(t, profile);
    });
    // (4) Only a token that passed §6.1 and §6.2 can raise the alert.
    if (isDebugMode(t)) {
        reportDebugMode(events, deps);
    }
    await step("audience", () => {
        checkAudience(t, profile);
    });
    await step("time", () => {
        checkTime(t, profile, deps.now());
    });
    await step("nonce", () => {
        checkNonce(t, expected);
    });
    await step("platform", () => {
        checkPlatform(t, profile);
    });
    await step("support_attributes", () => {
        checkSupportAttributes(t);
    });
    const signerKeyIds = await step("image", () => checkImage(t, profile));
    await step("launch_config", () => checkLaunchConfig(t, profile, deps));
    // Every claim read below has been validated by the step named beside it.
    return createVerifiedAttestation({
        issuer: profile.issuer, // issuer
        audience: profile.expected_audience, // audience
        imageDigest: getPath(t.claims, ["submods", "container", "image_digest"]) as string, // image
        signerKeyIds,
        hwmodel: getPath(t.claims, ["hwmodel"]) as string, // platform
        issuedAtMs: (getPath(t.claims, ["iat"]) as number) * 1000, // time
        expiresAtMs: (getPath(t.claims, ["exp"]) as number) * 1000, // time
    });
}
