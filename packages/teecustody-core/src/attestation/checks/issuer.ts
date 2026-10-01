// §6.2 issuer check.
import { getPath } from "../../json.js";
import { AttestationError, type ParsedToken, type TrustProfile } from "../types.js";

export function checkIssuer(t: ParsedToken, p: TrustProfile): void {
    const iss = getPath(t.claims, ["iss"]);
    if (iss === undefined) {
        throw new AttestationError("CLAIM_MISSING", "issuer");
    }
    if (iss !== p.issuer) {
        throw new AttestationError("CLAIM_MISMATCH", "issuer");
    }
}
