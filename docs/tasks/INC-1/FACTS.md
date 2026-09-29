# INC-1 external facts (Confidential Space) — verification record

Owner: Tech Lead (values) · V-01 (verification columns). Spec §0 line 13 and PROJECT.md R3: every value below
is an external fact and MUST be confirmed against current official Google Cloud documentation before code
depends on it. Values are the Tech Lead's pre-verification baseline. V-01 fills `Source URL`, `Accessed`
and `Verdict` (`confirmed` | `differs: <actual>` | `not documented`). V-01 never edits the `Value` column;
any `differs`/`not documented` row is a CONTRACT_ISSUE and the Tech Lead amends this file before Wave 1 starts.

Every Wave 1+ task that encodes a row re-confirms it against the recorded URL and records URL + access date
in its Task Report.

| Id | Fact | Value (baseline) | Used by | Source URL | Accessed | Verdict |
|---|---|---|---|---|---|---|
| F-01 | Launcher socket path inside the container | `/run/container_launcher/teeserver.sock` | T-01, T-06, T-08, T-16 | | | |
| F-02 | Token endpoint | HTTP/1.1 `POST /v1/token`, `Host: localhost`, `Content-Type: application/json`, body object `{"audience": str, "token_type": str, "nonces": [str, ...]}`; success `200` whose entire body is the token (compact JWS text) | T-06, T-08 | | | |
| F-03 | Custom nonce limits | 0 to 6 nonces per request; each nonce 10 to 74 bytes inclusive | T-06, T-07, T-08 | | | |
| F-04 | Default token file (carries no custom nonce; MUST NOT be used, spec §5.1 step 2) | `/run/container_launcher/attestation_verifier_claims_token` | T-01, T-08, T-14 | | | |
| F-05 | `eat_nonce` claim shape | JSON string when exactly one nonce was requested; JSON array of strings when more than one | T-06, T-07, T-12 | | | |
| F-06 | Token JOSE header | compact JWS; `alg` = `RS256`; `kid` present; `typ` = `JWT` | T-07, T-10, T-11 | | | |
| F-07 | Google issuer, discovery URL, `jwks_uri` | issuer `https://confidentialcomputing.googleapis.com`; discovery `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`; record the current `jwks_uri` value and its origin | T-10, T-11, T-17 | | | |
| F-08 | Claim paths and JSON types | `iss` str; `aud` str; `exp`,`iat`,`nbf` integer NumericDate (s); `eat_nonce` per F-05; `hwmodel` str; `swname` str; `secboot` bool; `dbgstat` str; `submods.confidential_space.support_attributes` array of str; `submods.container.image_reference` str; `submods.container.image_digest` str `sha256:<64 lowercase hex>`; `submods.container.image_signatures` array of objects `{key_id, signature, signature_algorithm}`; `submods.container.args` array of str; `submods.container.env` object str→str | T-07, T-12, T-13, T-15 | | | |
| F-09 | Production `hwmodel` values | `GCP_AMD_SEV`, `GCP_INTEL_TDX` (record every currently documented value) | T-10, T-17 | | | |
| F-10 | Real token lifetime (sets `SIM_TOKEN_TTL`, spec §14) | 3600 s | T-01, T-07 | | | |
| F-11 | `image_signatures` entry encoding | `signature_algorithm` ∈ {`RSASSA_PSS_SHA256`, `RSASSA_PKCS1V15_SHA256`, `ECDSA_P256_SHA256`}; `key_id` = lowercase hex SHA-256 of the signer public key's DER SubjectPublicKeyInfo; `signature` = RFC 4648 §4 base64 (padded) of the raw signature; PSS salt length 32 | T-07, T-13, T-17 | | | |
| F-12 | Bytes covered by an image signature | UTF-8 of `{"critical":{"identity":{"docker-reference":"<R>"},"image":{"docker-manifest-digest":"<D>"},"type":"cosign container image signature"},"optional":null}` exactly (no whitespace, this key order), where D = `image_digest` and R = `image_reference` with any `@<digest>` suffix removed and then any `:<tag>` suffix on the last path segment removed | T-07, T-13 | | | |
| F-13 | Audience in the default token file | `https://sts.googleapis.com` | T-08 | | | |
| F-14 | `dbgstat` values | `disabled-since-boot` (production), `enabled` (debug) | T-07, T-12 | | | |
| F-15 | `swname` value; `support_attributes` values | `CONFIDENTIAL_SPACE`; `LATEST`, `STABLE`, `USABLE` | T-07, T-12 | | | |

Scope limits fixed by the Tech Lead (not external facts):
- `TOKEN_TYPE` = `OIDC` only (spec §6.1 "choose one ... implement only that path"; §14 default). PKI is not implemented.
- INC-1 verifies image signatures with `RSASSA_PSS_SHA256` and `RSASSA_PKCS1V15_SHA256` only. A profile signer key with `ECDSA_P256_SHA256` is rejected by `parseTrustProfile` (`UNSUPPORTED_ALGORITHM`); adding it later is an API change.
- If F-12 cannot be confirmed (the signed bytes are not reconstructible from token claims), spec §6.8 "valid signatures" cannot be enforced client-side as written. That is a `constraint-deviation` for the human, not a Tech Lead amendment.
