// Negative fixture: static imports and type-only imports are visible to ESLint and tsc.
import type { TrustProfile } from "./attestation/types.js";
import { verifyAttestation } from "./attestation/verify.js";

export const verify = verifyAttestation;
export type Profile = TrustProfile;
export const required = "required";
