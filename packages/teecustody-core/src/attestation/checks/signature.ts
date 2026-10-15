// §6.1 token signature check as deviated by D-043: ADR 0009 rules 2, 4, 5 and ADR 0012 rule 2 (INC-2-API §16.2).
import { utf8DecodeStrict } from "../../encoding.js";
import type { FetchResponse, RsaPublicJwk } from "../../capabilities.js";
import { getPath, isJsonObject, type JsonObject, type JsonValue } from "../../json.js";
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

// Own property only (json.ts getPath); a value inherited from Object.prototype never counts.
function own(object: JsonObject, member: string): JsonValue | undefined {
    return getPath(object, [member]);
}

// ADR 0009 rule 2, in order; runs before any fetch. Returns the header kid.
function checkHeader(t: ParsedToken): string {
    const alg = own(t.header, "alg");
    const kid = own(t.header, "kid");
    const typ = own(t.header, "typ");
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

// Fetches the JWKS through the injected Fetcher; any transport, status (a redirect included), size, UTF-8 or
// JSON-shape failure is UNTRUSTED_SIGNER (INC-2-API §16.2 step 2). Errors carry no response content (SR-11).
// The Fetcher receives exactly the profile's string, once per call (ADR 0012 rule 2).
async function fetchJwks(p: TrustProfile, deps: VerifierDeps): Promise<JsonObject> {
    let response: FetchResponse;
    try {
        response = await deps.fetcher.get(p.jwks_uri);
    } catch {
        return reject("UNTRUSTED_SIGNER");
    }
    if (response.status !== 200 || response.body.length > deps.limits.maxJwksBytes) {
        return reject("UNTRUSTED_SIGNER");
    }
    let parsed: JsonValue;
    try {
        parsed = JSON.parse(utf8DecodeStrict(response.body)) as JsonValue;
    } catch {
        return reject("UNTRUSTED_SIGNER");
    }
    if (!isJsonObject(parsed)) {
        return reject("UNTRUSTED_SIGNER");
    }
    return parsed;
}

// ADR 0009 rule 4 candidate filter: exact kid, RSA, signing use, RS256 or no alg, string n and e.
function candidateKey(entry: JsonValue, kid: string): RsaPublicJwk | undefined {
    if (!isJsonObject(entry)) {
        return undefined;
    }
    const use = own(entry, "use");
    const alg = own(entry, "alg");
    const n = own(entry, "n");
    const e = own(entry, "e");
    if (
        own(entry, "kid") !== kid ||
        own(entry, "kty") !== "RSA" ||
        (use !== undefined && use !== "sig") ||
        (alg !== undefined && alg !== "RS256") ||
        typeof n !== "string" ||
        typeof e !== "string"
    ) {
        return undefined;
    }
    return { kty: "RSA", n, e };
}

// ADR 0009 rule 4: exactly one candidate key; zero or duplicates reject.
function selectKey(jwks: JsonObject, kid: string): RsaPublicJwk {
    const keys = own(jwks, "keys");
    if (!Array.isArray(keys)) {
        return reject("UNTRUSTED_SIGNER");
    }
    const candidates = (keys as readonly JsonValue[]).flatMap((entry) => {
        const key = candidateKey(entry, kid);
        return key === undefined ? [] : [key];
    });
    const [key, ...others] = candidates;
    if (key === undefined || others.length > 0) {
        return reject("UNTRUSTED_SIGNER");
    }
    return key;
}

export async function checkSignature(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    const kid = checkHeader(t);
    const jwks = await fetchJwks(p, deps);
    const jwk = selectKey(jwks, kid);
    // unknown: an adapter is outside this module's control; only a boolean true verifies.
    let valid: unknown;
    try {
        valid = await deps.crypto.verifySignature(
            "RSASSA_PKCS1V15_SHA256",
            { format: "jwk", jwk },
            t.signingInput,
            t.signature,
        );
    } catch {
        return reject("UNTRUSTED_SIGNER");
    }
    if (valid !== true) {
        reject("UNTRUSTED_SIGNER");
    }
}
