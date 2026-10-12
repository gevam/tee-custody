# ADR-0009: Attestation token JWS handling (RS256, no JOSE library)

Status: Accepted — Security Architect sign-off 2026-09-30 (test conditions: THREAT_MODEL.md review log 2026-09-30; SR-1)   Date: 2026-09-30   Author: architect   (INC-1 CONTRACT_ISSUE R-2 / CI-2; WAVES.md)

## Context
Confidential Space OIDC attestation tokens are compact JWS. V-01 verified the following on 2026-09-30:
- **F-06.** The discovery document's `id_token_signing_alg_values_supported` is `["RS256"]`. Live JWKS keys are `kty` RSA, `alg` RS256, and carry a `kid`, and key selection is by header `kid`. `typ` `JWT` appears only in a docs sample. The complete header member set of a real token has **not** been observed.
- **F-07.** The issuer and discovery URL are `https://confidentialcomputing.googleapis.com[/.well-known/openid-configuration]`. `jwks_uri` is `https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`, whose origin differs from the issuer's.
- **F-10.** Token lifetime is 3600 s. JWS appears in three places:
- **Simulator.** `teecustody-sim` must mint RS256 tokens. It must also mint deliberately broken ones: `alg: none`, corrupted signatures, and claims altered then re-signed (spec §15.3, API.md §G).
- **Core client.** `verifyAttestation` must verify the token signature against the JWKS named by the trust profile (spec §6.1).
- **Python workload.** It never verifies its own token. It trusts only the launcher socket (spec §11), and `parse_token_metadata` reads `iat`/`exp` as untrusted metadata.

Spec §0 says: "Do not compose primitives by hand where a standard construction exists." The crypto allow-list (`framework.yaml → security.dependency_policy`) has no JOSE library. Adding one needs an ADR, Security Architect sign-off and, per ADR 0003, a human decision. Core must reach platform crypto only through the `Crypto` capability (NFR-6, PROJECT.md goal 5).

## Options considered
1. **Project-owned compact-JWS framing, pinned to RS256, over audited RSA primitives.**
   - Python simulator: base64url framing, then `cryptography` RSA-2048 `PKCS1v15()` + `SHA256()`.
   - Core: `parseToken` splits and decodes the token. `checkSignature` calls `Crypto.verifySignature("RSASSA_PKCS1V15_SHA256", jwk, signingInput, signature)`, which WebCrypto or Node `crypto` implements.
   - Pros: the header `alg` never selects an algorithm, so algorithm confusion and `none` are impossible by construction. There is no HMAC path. Core keeps its capability boundary. No new dependency. The simulator can mint any malformed token directly.
   - Cons: about 60 lines of security-path framing that the project owns. The Security Architect must agree that this framing does not "compose primitives by hand".
2. **Adopt a JOSE library**: `jose` (panva, MIT, no dependencies) in Core, and PyJWT or `joserfc` in the simulator.
   - Pros: a widely used implementation of RFC 7515.
   - Cons:
     - To my knowledge `jose` calls the global WebCrypto directly and has no injectable crypto. It would bypass the `Crypto` capability that mobile needs. *(Not verified against its current source.)*
     - It adds a crypto dependency to the CSP-scanned Core bundle (SR-13). That needs a constraint decision.
     - Core cannot use its remote JWKS set, because that calls `fetch`. We would still write discovery, JWKS retrieval, key selection and every §6 claim check. The library would replace only the framing and the signature call.
     - Its algorithm agility must be configured down to RS256. Mis-set agility is the historical source of JOSE CVEs.
     - The simulator would still need hand-framing for every negative vector, giving two code paths for the same bytes.
3. **Option 1 in production, plus `jose` as a test-only differential oracle.** Pros: an independent cross-check. Cons: still adds a crypto dependency, needing sign-off. A published known-answer test gives an independent oracle without any dependency.

## Decision
Option 1, because the only standard-defined part left to hand-code is RFC 7515 §5.2's fixed signing-input encoding (base64url and `.`). The signature primitive stays in audited implementations. Pinning a single algorithm removes the agility that JOSE libraries exist to manage, and removes the surface where their vulnerabilities lived. The independent oracle is RFC 7515 Appendix A.2 (RS256), not a library.

Normative rules (T-07, T-10, T-11 contracts must match):
1. **Parsing (`parseToken`, check `token`, `MALFORMED`).**
   - UTF-8 length ≤ `maxTokenBytes`.
   - Exactly three segments. Segments 1–2 are non-empty. Segment 3 may be empty at parse time, so that `alg_none` is classified by rule 2.
   - Base64url decoding is strict: RFC 4648 §5 alphabet, no padding, length mod 4 ≠ 1, and unused trailing bits must be zero (canonical).
   - Header and payload are strict UTF-8 JSON objects.
   - `signingInput` is the received ASCII `seg1 "." seg2`, never re-serialized.
2. **Header (`checkSignature`, check `signature`), in this order. Every step before 6 runs before any fetch.**
   1. `alg` absent, not a string, or not exactly `"RS256"` (case-sensitive) → `UNSUPPORTED_ALGORITHM`.
   2. Any member other than `alg`, `kid`, `typ` → `UNSUPPORTED_ALGORITHM`. This covers `crit`, `b64`, `zip`, `enc`, `cty`, `jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`. No header member is ever used to locate or supply a key. `alg` and `kid` are confirmed by F-06. The complete member set is not.
      - The first real Confidential Space token captured must confirm the set, and the Tech Lead records the header member names in FACTS. This happens at the INC-3 smoke run at the latest, or earlier if a token can be obtained. The scheduled smoke run (NFR-11) re-checks it.
      - An unexpected member fails closed, which is an availability failure only. The Tech Lead then adds that exact name through a contract amendment. Never a wildcard.
   3. `typ` is optional, because F-06 only saw it in a docs sample. If present and not `"JWT"` → `MALFORMED`.
   4. `kid` absent, not a string, empty, or longer than 256 characters → `UNTRUSTED_SIGNER`.
   5. Zero-length signature → `UNTRUSTED_SIGNER`.
3. **Key retrieval.** *(Superseded 2026-10-11 by ADR 0012 / D-043: Core fetches exactly the profile's pinned `jwks_uri` and never fetches discovery. The text below records the INC-1 behaviour; the "no JWKS cache" and "any failure → `UNTRUSTED_SIGNER`" rules still apply.)*
   - Fetch the profile's `discovery_url` through the injected `Fetcher`. Its `issuer` must equal the profile's `issuer`. The origin of `jwks_uri` must equal the profile's `jwks_origin`, which in production is exactly `https://www.googleapis.com` (F-07).
   - That origin also serves the JWKS of every Google service account, so the origin match is defence in depth only. The authenticity of the specific `jwks_uri` comes from the TLS-fetched Google discovery document. The origin check is not relaxed to reach that document.
   - Fetch `jwks_uri`. Size limits come from `VerifierLimits`.
   - Any failure → `UNTRUSTED_SIGNER`.
   - **No JWKS cache in INC-1.** Each `verifyAttestation` fetches both documents once, so key rotation is always seen fresh. An unknown `kid` is rejected, with no refetch.
   - A cache, if INC-2 load needs one, is a separate ADR. It would be per `TeeClient` instance, in memory only, with bounded TTL and at most one rate-limited refresh on an unknown `kid`.
4. **Key selection.** Live Google keys carry `alg` `RS256` and `kty` RSA (F-06), so this filter accepts them. Candidates are JWKs with `kid` equal to the header `kid` (exact string equality, no normalization), `kty` `"RSA"`, `use` absent or `"sig"`, `alg` absent or `"RS256"`, and string `n` and `e`. Exactly one candidate is required. Zero or duplicates → `UNTRUSTED_SIGNER`.
5. **Verification.** `Crypto.verifySignature("RSASSA_PKCS1V15_SHA256", {format: "jwk", jwk: {kty, n, e}}, signingInput, signature)`. The algorithm is a literal. A modulus under 2048 bits makes the adapter reject with `INVALID_ARGUMENT`. `false` or any rejection → `UNTRUSTED_SIGNER`.
6. **Duplicate JSON members are not detected.** The header cannot change the algorithm or the key source. The payload is trusted only after the issuer's signature verifies. Last-wins parsing therefore creates no confusion. Not detecting duplicates avoids a hand-written JSON parser.
7. **Simulator (T-07).**
   - Issuer key: RSA-2048 with e = 65537, signed through `cryptography` only.
   - Token lifetime `SIM_TOKEN_TTL` is 3600 s (F-10).
   - Simulator discovery advertises `id_token_signing_alg_values_supported: ["RS256"]`, matching F-06.
   - Simulator JWKS entries carry `kty`, `alg` `RS256`, `use` `sig`, `kid`, `n`, `e`.
   - The header is compact JSON `{"alg":"RS256","kid":<issuer_kid>,"typ":"JWT"}`.
   - Negative vectors are framed by the same helper, with the alteration applied before or after signing as API.md §G states.
8. **Python-side verification.**
   - None in `teecustody`. `parse_token_metadata` output is never a trust input.
   - Python contract tests that check simulator tokens verify with `cryptography` directly, in test code.
9. **Development transport.** The development profile's discovery and JWKS URLs are `http:` on loopback, because the simulator issuer is plain HTTP on 127.0.0.1.
   - `parseTrustProfile` accepts `http:` only for `profile_kind: "development"` and only on loopback hosts. Production profiles require `https:`.
   - `profile_kind` is read only by `parseTrustProfile`. No §6 check function reads it.
   - The Security Architect is asked to confirm that this is an anchor difference (spec §15.4), not a relaxed check (I13).

Test obligations (security path, 100% branch coverage):
- **KAT, sign.** The simulator framing and signing helper, given the RFC 7515 A.2 private key and the A.2 header and payload octets, reproduces the A.2 compact serialization byte for byte. PKCS#1 v1.5 is deterministic, so this is possible.
- **KAT, verify.** Core `parseToken` on the A.2 token yields the A.2 signing input. `Crypto.verifySignature` (Node adapter) accepts it with the A.2 public JWK. A one-bit flip in each of the three segments rejects.
- **Header matrix.** Each of the following yields its stated code and the fetcher is never called:
  - `alg` values `none`, absent, non-string, `rs256`, `HS256`, `RS384`, `RS512`, `PS256`, `ES256`;
  - each forbidden member listed in rule 2.2;
  - `typ` values other than `JWT`;
  - `kid` absent, empty, non-string, or 257 characters;
  - an empty signature.
- **Algorithm confusion.** An HS256 token whose MAC key is the RSA public key (as JWK JSON, and as SPKI DER) → `UNSUPPORTED_ALGORITHM`.
- **Embedded key.** A token signed by an attacker key and carrying that key in `jwk`, or pointing to it with `jku` → `UNSUPPORTED_ALGORITHM`.
- **JWKS matrix** (T-11 criterion 4). Also: a 1024-bit key → `UNTRUSTED_SIGNER`; the same `kid` with a different key → `UNTRUSTED_SIGNER`.
- **Base64url canonicality** (T-02 `encoding.ts`): non-zero trailing bits, length mod 4 = 1, padding, and `+` or `/` are each rejected.
- **Existing vectors.** `alg_none`, `token_signature_corrupted` and `debug_bad_signature` (API.md §G), and the §13.9 production-profile rejection of a simulator token.

## Consequences
- Positive:
  - No new dependency.
  - Algorithm confusion, `none` and embedded-key attacks are structurally unreachable.
  - Core keeps its platform-neutral `Crypto` boundary.
  - The simulator controls every byte of every negative vector.
- Negative / accepted trade-offs:
  - The project owns the framing code and its review.
  - An unannounced Google header change (a new member, or a new `alg`) fails closed until the allow-list is amended. That is an availability risk, not a security one. The scheduled Confidential Space smoke run (NFR-11) detects it.
- Security implications:
  - T-07, T-10 and T-11 are STRONG-tier and security-path.
  - If the Security Architect judges that option 1 conflicts with spec §0, it becomes a `constraint-deviation` for the human, with option 2 as the alternative. That would require the ADR 0003 dependency process and an ADR on how `jose` coexists with the `Crypto` capability.
- What this makes harder later, and how we'd undo it:
  - PKI token type (`x5c`) or another `alg` requires a new ADR.
  - Replacing the framing with a library touches only `parseToken`/`checkSignature` and the simulator helper. The `Crypto.verifySignature` contract and the §6 checks are unchanged.

## Scope note: image signatures (F-12)
This ADR covers only the token JWS, which is unaffected by F-12. `Crypto.verifySignature` is also the method that would verify image signatures under F-12 outcome (b). Nothing here decides F-12, which is a pending human constraint-deviation.

## Amendments
- 2026-09-30: aligned with the V-01 verdicts F-06, F-07 and F-10, as follows:
  - `typ` is optional.
  - The header member set must be confirmed on the first real token.
  - The production JWKS origin is pinned to `https://www.googleapis.com`.
  - Simulator discovery and JWKS now match the verified shapes.
- 2026-10-11 (D-043, ADR 0012):
  - Rule 3 is superseded: there is no runtime discovery fetch; Core fetches only the pinned `jwks_uri`.
  - Rule 9 now covers only the JWKS URL. Development profiles carry a loopback `jwks_uri` (`http:` allowed) whose path is exactly `/jwks`.
  - The "JWKS matrix" tests remain. The discovery tests are replaced by the SR-1 list in INC-2-API §16.9.
