// Positive fixture: Core never fetches or names an OIDC discovery document (D-043, ADR 0012).
// ruleid: tc-core-no-oidc-discovery
const DISCOVERY_PATH = "/.well-known/openid-configuration";

export function discoveryUrl(issuer: string): string {
    // ruleid: tc-core-no-oidc-discovery
    // The issuer's openid-configuration names the JWKS location.
    return `${issuer}${DISCOVERY_PATH}`;
}
