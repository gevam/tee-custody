// §6.1 token signature check; ADR 0009 rules 2–5.
import { utf8DecodeStrict } from "../../encoding.js";
import type { JsonObject } from "../../json.js";
import type { ParsedToken, TrustProfile, VerifierDeps } from "../types.js";

async function fetchJson(deps: VerifierDeps, url: string): Promise<JsonObject> {
    const response = await deps.fetcher.get(url);
    return JSON.parse(utf8DecodeStrict(response.body)) as JsonObject;
}

export async function checkSignature(
    t: ParsedToken,
    p: TrustProfile,
    deps: VerifierDeps,
): Promise<void> {
    const discovery = await fetchJson(deps, p.discovery_url);
    const jwks = await fetchJson(deps, discovery["jwks_uri"] as string);
    const keys = jwks["keys"] as readonly JsonObject[];
    const key = keys.find((k) => k["kid"] === t.header["kid"]) as JsonObject;
    await deps.crypto.verifySignature(
        "RSASSA_PKCS1V15_SHA256",
        { format: "jwk", jwk: { kty: "RSA", n: key["n"] as string, e: key["e"] as string } },
        t.signingInput,
        t.signature,
    );
}
