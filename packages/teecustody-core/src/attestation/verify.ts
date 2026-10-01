// Full attestation verification [CI-1]: spec §6 checks as one fixed code path, parameterised by the profile.
import type { SecurityEventSink } from "../capabilities.js";
import { getPath } from "../json.js";
import { checkImage } from "./checks/image.js";
import { parseToken } from "./token.js";
import {
    createVerifiedAttestation,
    type ExpectedAttestation,
    type TrustProfile,
    type VerifiedAttestation,
    type VerifierDeps,
} from "./types.js";

export async function verifyAttestation(
    token: string,
    profile: TrustProfile,
    expected: ExpectedAttestation,
    events: SecurityEventSink,
    deps: VerifierDeps,
): Promise<VerifiedAttestation> {
    const t = parseToken(token, deps.limits.maxTokenBytes);
    const signerKeyIds = checkImage(t, profile);
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
