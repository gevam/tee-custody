// Negative fixture: verification vocabulary without a skip switch.
export function verifyAttestation(token: string): string {
    return token;
}
export const VERIFIED = "verified";
// T-35 (TL-13): the bare profile CLI refusal code is not a switch.
export const TLS_REFUSAL = "INSECURE_TLS_ENVIRONMENT";
