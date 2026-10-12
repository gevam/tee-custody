# ADR-0012: Pinned `jwks_uri` in the trust profile; discovery binding checked at build time

Status: Accepted — human constraint-deviation D-043 (spec §6.1, CI-2-1), 2026-10-11. The Security Architect re-checks the contracts in docs/INC-2-API.md §16 and then sets T-29 to "mitigated by design".   Date: 2026-10-11   Author: architect   (INC-2; contracts in docs/INC-2-API.md §16)

Supersedes ADR 0009 rule 3 ("Key retrieval") and the discovery half of ADR 0009 rule 9. Amends ADR 0008 (`connect-src`) and the ADR 0002 amendment of 2026-09-30 (trust-profile fields).

## Context
- **Spec §6.1** says the client fetches the OIDC discovery document over TLS from the exact issuer origin at runtime and takes `jwks_uri` from it.
- **Spec §10.2** places the JWKS location in the compiled trust profile, which is never fetched from the server at runtime.
- **INC-1 (T-11, ADR 0009 rule 3)** implemented runtime discovery. The client fetched discovery, required `issuer` to be equal, required the origin of `jwks_uri` to equal `jwks_origin` (`https://www.googleapis.com`), and then fetched the JWKS.
- **CI-2-1 (verified 2026-10-06).** Google's discovery endpoint (`confidentialcomputing.googleapis.com`) sends no `Access-Control-Allow-Origin` header. The JWKS endpoint (`www.googleapis.com/service_accounts/...`) does send one. As a result, a browser can fetch the JWKS but cannot read discovery, and every browser verification fails closed.
- **T-29 (THREAT_MODEL).** `https://www.googleapis.com` serves the JWKS of every Google service account. INC-1's origin-only pin therefore lets any party who controls the `jwks_uri` string point a client at a JWKS they own on the same origin. Fetching discovery directly from Google over TLS is the only thing that closes this hole, and relaying discovery would reopen it.
- **Requirement I13.** Node and browsers must use one code path. Platform-dependent verification is not allowed.

## Options considered
1. **A — pin the exact `jwks_uri` in the compiled profile, with no runtime discovery fetch.** A build tool checks the discovery binding, and a scheduled job re-checks it.
   - Pros: one code path for every client. Closes T-29 by construction, because no runtime input chooses the key URL. Removes a runtime network dependency. Matches spec §10.2.
   - Cons: deviates from §6.1's runtime discovery step. If Google changes the JWKS URI, clients fail closed until a release.
2. **B — relay discovery through the gateway, plus an exact-URI pin.**
   - Cons: adds an untrusted ingress whose content cannot matter, since the pin alone decides. It is still a deviation.
3. **C — `TOKEN_TYPE=PKI`.**
   - Cons: needs X.509 path validation in the browser. WebCrypto has none, so this would mean ASN.1 code or a new crypto dependency, which conflicts with ADR 0009. It also replaces the INC-1 OIDC path.
4. **A′ — pin the URI in browsers but keep runtime discovery in Node.** Rejected: it violates I13 (one code path).

## Decision
Option A, as decided by the human in D-043. Normative rules (INC-2-API §16 holds the exact contracts):

1. **Trust profile v2.**
   - `profile_version` is 2.
   - `jwks_uri` is a required field: an exact, canonical URL string.
   - `discovery_url` and `jwks_origin` are removed. A consumer that needs the JWKS origin (CSP) derives it with `new URL(jwks_uri).origin`.
   - A production profile's `jwks_uri` must equal the FACTS F-07 value exactly. That value is a constant in Core, alongside the Google issuer constant.
   - A development profile's `jwks_uri` is a canonical loopback URL whose path is exactly `/jwks`.
   - `parseTrustProfile` rejects every v1 profile.
2. **Core verifier.** `checkSignature` fetches exactly `profile.jwks_uri` through the injected `Fetcher`, once per verification, with no redirects (D2-14). Core never fetches, parses or names a discovery document. Header rules, key selection, the RSA ≥ 2048 rule, the `UNTRUSTED_SIGNER` mapping and the §6.2 token `iss` check are unchanged.
3. **Build-time binding check.** `teecustody-profile check-discovery` runs in the host's production build and fails the build unless all of these hold:
   - the discovery document, fetched over TLS from the exact Google discovery URL, has an `issuer` equal to the profile's `issuer`;
   - its `jwks_uri` is string-equal to the profile's `jwks_uri`;
   - that `jwks_uri` serves at least one usable RS256 key.

   The check has no skip flag and no offline mode.
4. **Scheduled check (NFR-11).** A scheduled and on-demand CI job runs the same command against real Google endpoints, using an inert production-shaped fixture profile. It also probes CORS on the JWKS, and reports whether discovery has gained CORS, which is a revisit trigger in D-043. The job is also part of the INC-5 pre-release checklist.
5. **Simulator parity.**
   - The simulator JWKS route sends `Access-Control-Allow-Origin` (the V-2.7 value; `*` expected) and answers a preflight. The discovery route sends no CORS header, exactly like Google.
   - `teecustody-sim profile` emits the exact loopback `jwks_uri`.
   - The simulator also serves an "attacker" JWKS at `/attacker/jwks` on the same origin, so that T-29 can be exercised end to end.
6. **Vectors.** Every vector `http` map holds only JWKS URLs, never a discovery URL. A verifier that fetches discovery therefore fails the `valid` case. The attestation suite gains the T-29 rows `jwks_other_path` and `jwks_other_path_same_kid`. The CDDL and `proto` are unchanged: the profile is a build artifact, not a wire structure.
7. **CSP (SR-13).** `connect-src` names the JWKS origin derived from `jwks_uri` and never a discovery origin.

## Consequences
- **Positive.**
  - T-29 is closed by construction: no runtime value chooses the key URL.
  - The browser path works.
  - Node and browsers share one code path.
  - Each verification makes one network fetch instead of two.
  - The pinned production constant is checked twice: once at host build time, and continuously by the scheduled job.
- **Negative / accepted trade-offs.**
  - **Availability.** A Google JWKS URI change, or a change to its CORS header, makes clients fail closed until the hosts ship a new build (residual T-29, Low, accepted in D-043). Because the production constant lives in Core (rule 1), a URI change also needs a Core patch release, not only a profile rebuild. The scheduled check detects the change first.
  - **Production builds need network access to Google.** An offline production build fails (`DISCOVERY_UNAVAILABLE`). This is deliberate (no skip flag, I13).
  - `VerifierLimits.maxDiscoveryBytes` becomes an ignored, optional, deprecated field so that INC-2 Wave-0 code and tests keep compiling. It must be removed before v1.0.0 (DEBT entry, expiry INC-5).
  - The `teecustody-profile` CLI is Node-only and must stay unreachable from the browser scan entry. Its `node:` imports would otherwise break the single-external rule of ADR 0011 C7a.1 (D-045).
  - Every v1 trust profile, and every v1 `sim-state.json`, stops working. A developer re-runs `teecustody-sim serve`/`up` and `teecustody-sim profile`.
- **Security implications.**
  - Spec §6.1 runtime discovery is replaced by build-time discovery (constraint-deviation D-043). The token `iss` check (§6.2) still binds the issuer at runtime.
  - Changes under `spec/vectors`, any trust-profile-shaped fixture, and the traceability row for §6.1 return to the human (`escalation.always_human`).
  - Every changed file is on `security.paths` and is STRONG-tier, except vector regeneration, which is FAST and human-gated.
- **Undoing it.** If Google adds CORS to discovery, runtime discovery could return as an extra check. The pin would stay authoritative, so this is a profile v3, a new ADR, and a human decision. The Core change is confined to `profile.ts` and `checks/signature.ts`.
