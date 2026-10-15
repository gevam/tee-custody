// Build-time discovery binding (INC-2-API §16.5; D-043, ADR 0012 rule 3; SR-1, SR-11). A host's production build
// fails unless the issuer's discovery document names the profile's `issuer` and `jwks_uri` exactly. Not exported
// from src/index.ts; no DOM or Node imports, so it is safe in either the browser or the CLI graph.
import {
    CapabilityError,
    isJsonObject,
    utf8DecodeStrict,
    type FetchResponse,
    type Fetcher,
    type JsonObject,
    type JsonValue,
    type TrustProfile,
} from "@teecustody/core";

export const GOOGLE_DISCOVERY_URL =
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"; // F-07

export type DiscoveryBindingErrorCode =
    | "INVALID_ARGUMENT"
    | "DISCOVERY_UNAVAILABLE"
    | "DISCOVERY_INVALID"
    | "ISSUER_MISMATCH"
    | "JWKS_URI_MISMATCH"
    | "JWKS_UNAVAILABLE"
    | "JWKS_INVALID";

/** The message is the code; an error never carries a URL or a document body (SR-11). */
export class DiscoveryBindingError extends Error {
    constructor(readonly code: DiscoveryBindingErrorCode) {
        super(code);
    }
}

export interface DiscoveryBindingInput {
    readonly profile: TrustProfile;
    readonly discoveryUrl: string;
}

export interface DiscoveryBindingDeps {
    readonly fetcher: Fetcher;
    readonly maxDocumentBytes: number;
}

export interface DiscoveryBindingReport {
    readonly issuer: string;
    readonly jwksUri: string;
    readonly usableKeyCount: number;
}

const DISCOVERY_PATH = "/.well-known/openid-configuration";
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(["127.0.0.1", "localhost", "[::1]"]);
const FETCH_PROTOCOLS: ReadonlySet<string> = new Set(["http:", "https:"]);
const MAX_KID_LENGTH = 256;

// Step 1, development: a canonical loopback discovery URL on the origin that serves the pinned JWKS.
function isDevelopmentDiscoveryUrl(discoveryUrl: string, jwksUri: string): boolean {
    if (discoveryUrl.includes("?") || discoveryUrl.includes("#")) {
        return false;
    }
    let url: URL;
    try {
        url = new URL(discoveryUrl);
    } catch {
        return false;
    }
    return (
        url.href === discoveryUrl &&
        url.username === "" &&
        url.password === "" &&
        FETCH_PROTOCOLS.has(url.protocol) &&
        LOOPBACK_HOSTS.has(url.hostname) &&
        url.pathname === DISCOVERY_PATH &&
        url.origin === new URL(jwksUri).origin
    );
}

function isValidArgument(input: DiscoveryBindingInput, maxDocumentBytes: number): boolean {
    if (!Number.isSafeInteger(maxDocumentBytes) || maxDocumentBytes <= 0) {
        return false;
    }
    if (input.profile.profile_kind === "production") {
        return input.discoveryUrl === GOOGLE_DISCOVERY_URL;
    }
    return isDevelopmentDiscoveryUrl(input.discoveryUrl, input.profile.jwks_uri);
}

// One fetch, no retry. A body that is oversize (here, or the Fetcher's own size or Content-Length rejection,
// CapabilityError("INVALID_RESPONSE"), A3 R2), not strict UTF-8, not JSON or not a JSON object is `invalid`. Any
// other rejection or throw, or a status other than 200, is `unavailable`.
async function fetchObject(
    fetcher: Fetcher,
    url: string,
    maxDocumentBytes: number,
    unavailable: DiscoveryBindingErrorCode,
    invalid: DiscoveryBindingErrorCode,
): Promise<JsonObject> {
    let response: FetchResponse;
    try {
        response = await fetcher.get(url);
    } catch (error) {
        const oversize = error instanceof CapabilityError && error.code === "INVALID_RESPONSE";
        throw new DiscoveryBindingError(oversize ? invalid : unavailable);
    }
    if (response.status !== 200) {
        throw new DiscoveryBindingError(unavailable);
    }
    if (response.body.byteLength > maxDocumentBytes) {
        throw new DiscoveryBindingError(invalid);
    }
    let parsed: JsonValue;
    try {
        parsed = JSON.parse(utf8DecodeStrict(response.body)) as JsonValue;
    } catch {
        throw new DiscoveryBindingError(invalid);
    }
    if (!isJsonObject(parsed)) {
        throw new DiscoveryBindingError(invalid);
    }
    return parsed;
}

function ownMember(document: JsonObject, key: string): JsonValue | undefined {
    return Object.hasOwn(document, key) ? document[key] : undefined;
}

// Step 6: ADR 0009 rule 4's filter, applied to any kid.
function isUsableKey(entry: JsonValue): boolean {
    if (!isJsonObject(entry)) {
        return false;
    }
    const kid = ownMember(entry, "kid");
    const use = ownMember(entry, "use");
    const alg = ownMember(entry, "alg");
    return (
        ownMember(entry, "kty") === "RSA" &&
        typeof kid === "string" &&
        kid.length >= 1 &&
        kid.length <= MAX_KID_LENGTH &&
        (use === undefined || use === "sig") &&
        (alg === undefined || alg === "RS256") &&
        typeof ownMember(entry, "n") === "string" &&
        typeof ownMember(entry, "e") === "string"
    );
}

/**
 * INC-2-API §16.5 steps 1-7: exactly two fetches (discovery, then the profile's pinned JWKS), no retry, no cache.
 * Issuer and `jwks_uri` are compared as exact strings with no normalisation. Every failure is a
 * `DiscoveryBindingError` carrying only its code.
 */
export async function checkDiscoveryBinding(
    input: DiscoveryBindingInput,
    deps: DiscoveryBindingDeps,
): Promise<DiscoveryBindingReport> {
    const { profile, discoveryUrl } = input;
    const { fetcher, maxDocumentBytes } = deps;
    if (!isValidArgument(input, maxDocumentBytes)) {
        throw new DiscoveryBindingError("INVALID_ARGUMENT");
    }
    const discovery = await fetchObject(
        fetcher,
        discoveryUrl,
        maxDocumentBytes,
        "DISCOVERY_UNAVAILABLE",
        "DISCOVERY_INVALID",
    );
    if (ownMember(discovery, "issuer") !== profile.issuer) {
        throw new DiscoveryBindingError("ISSUER_MISMATCH");
    }
    if (ownMember(discovery, "jwks_uri") !== profile.jwks_uri) {
        throw new DiscoveryBindingError("JWKS_URI_MISMATCH");
    }
    const jwks = await fetchObject(
        fetcher,
        profile.jwks_uri,
        maxDocumentBytes,
        "JWKS_UNAVAILABLE",
        "JWKS_INVALID",
    );
    const keys = ownMember(jwks, "keys");
    if (!Array.isArray(keys)) {
        throw new DiscoveryBindingError("JWKS_INVALID");
    }
    const usableKeyCount = (keys as readonly JsonValue[]).filter(isUsableKey).length;
    if (usableKeyCount === 0) {
        throw new DiscoveryBindingError("JWKS_INVALID");
    }
    return { issuer: profile.issuer, jwksUri: profile.jwks_uri, usableKeyCount };
}
