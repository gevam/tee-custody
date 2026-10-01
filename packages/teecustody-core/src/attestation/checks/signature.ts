// §6.1 token signature check; ADR 0009 rules 2–5.
import { utf8DecodeStrict } from "../../encoding.js";
import type { RsaPublicJwk } from "../../capabilities.js";
import { isJsonObject, type JsonObject, type JsonValue } from "../../json.js";
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

// Fetches one document through the injected Fetcher; any transport, status, size, UTF-8 or JSON-shape
// failure is UNTRUSTED_SIGNER (ADR 0009 rule 3). Errors carry no response content (SR-11).
async function fetchJsonObject(
    deps: VerifierDeps,
    url: string,
    maxBytes: number,
): Promise<JsonObject> {
    let parsed: JsonValue;
    try {
        const response = await deps.fetcher.get(url);
        if (response.status !== 200 || response.body.length > maxBytes) {
            return reject("UNTRUSTED_SIGNER");
        }
        parsed = JSON.parse(utf8DecodeStrict(response.body)) as JsonValue;
    } catch {
        return reject("UNTRUSTED_SIGNER");
    }
    if (!isJsonObject(parsed)) {
        return reject("UNTRUSTED_SIGNER");
    }
    return parsed;
}

// ADR 0009 rule 3: the discovery issuer matches the profile; jwks_uri is on the profile's JWKS origin.
function jwksUriOf(discovery: JsonObject, p: TrustProfile): string {
    const { issuer, jwks_uri: jwksUri } = discovery;
    if (issuer !== p.issuer || typeof jwksUri !== "string") {
        return reject("UNTRUSTED_SIGNER");
    }
    let url: URL;
    try {
        url = new URL(jwksUri);
    } catch {
        return reject("UNTRUSTED_SIGNER");
    }
    if (url.username !== "" || url.password !== "" || url.origin !== p.jwks_origin) {
        return reject("UNTRUSTED_SIGNER");
    }
    return jwksUri;
}

// ADR 0009 rule 4 candidate filter: exact kid, RSA, signing use, RS256 or no alg, string n and e.
function candidateKey(entry: JsonValue, kid: string): RsaPublicJwk | undefined {
    if (!isJsonObject(entry)) {
        return undefined;
    }
    const { kid: entryKid, kty, use, alg, n, e } = entry;
    if (
        entryKid !== kid ||
        kty !== "RSA" ||
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
    const keys = jwks["keys"];
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
    const discovery = await fetchJsonObject(deps, p.discovery_url, deps.limits.maxDiscoveryBytes);
    const jwksUri = jwksUriOf(discovery, p);
    const jwks = await fetchJsonObject(deps, jwksUri, deps.limits.maxJwksBytes);
    const jwk = selectKey(jwks, kid);
    let valid: boolean;
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
    if (!valid) {
        reject("UNTRUSTED_SIGNER");
    }
}
