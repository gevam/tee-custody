// Full attestation verification [CI-1]. Stub → T-15.
import type { SecurityEventSink } from "../capabilities.js";
import type {
    ExpectedAttestation,
    TrustProfile,
    VerifiedAttestation,
    VerifierDeps,
} from "./types.js";

export function verifyAttestation(
    token: string,
    profile: TrustProfile,
    expected: ExpectedAttestation,
    events: SecurityEventSink,
    deps: VerifierDeps,
): Promise<VerifiedAttestation> {
    throw new Error("NOT_IMPLEMENTED: T-15");
}
