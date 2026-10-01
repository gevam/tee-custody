// §6.1 token signature check; ADR 0009 rules 2–5.
import { utf8DecodeStrict } from "../../encoding.js";
import type { JsonObject } from "../../json.js";
import {
    AttestationError,
    type AttestationErrorCode,
    type ParsedToken,
    type TrustProfile,
    type VerifierDeps,
} from "../types.js";

const ALLOWED_HEADER_MEMBERS: ReadonlySet<string> = new Set(["alg", "kid", "typ"]);
const MAX_KID_LENGTH = 256;

function reject(code: AttestationErrorCode): never {
    throw new AttestationError(code, "signature");
}

// ADR 0009 rule 2, in order; runs before any fetch. Returns the header kid.
function checkHeader(t: ParsedToken): string {
    const { alg, kid, typ } = t.header;
    if (alg !== "RS256") {
        reject("UNSUPPORTED_ALGORITHM");
    }
    if (Object.keys(t.header).some((member) => !ALLOWED_HEADER_MEMBERS.has(member))) {
        reject("UNSUPPORTED_ALGORITHM");
    }
    if (typ !== undefined && typ !== "JWT") {
        reject("MALFORMED");
    }
    if (typeof kid !== "string" || kid.length === 0 || kid.length > MAX_KID_LENGTH) {
        reject("UNTRUSTED_SIGNER");
    }
    if (t.signature.length === 0) {
        reject("UNTRUSTED_SIGNER");
    }
    return kid;
}

async function fetchJson(deps: VerifierDeps, url: string): Promise<JsonObject> {
    const response = await deps.fetcher.get(url);
    return JSON.parse(utf8DecodeStrict(response.body)) as JsonObject;
}

export async function checkSignature(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    const kid = checkHeader(t);
    const discovery = await fetchJson(deps, p.discovery_url);
    const jwks = await fetchJson(deps, discovery["jwks_uri"] as string);
    const keys = jwks["keys"] as readonly JsonObject[];
    const key = keys.find((k) => k["kid"] === kid) as JsonObject;
    await deps.crypto.verifySignature(
        "RSASSA_PKCS1V15_SHA256",
        { format: "jwk", jwk: { kty: "RSA", n: key["n"] as string, e: key["e"] as string } },
        t.signingInput,
        t.signature,
    );
}
