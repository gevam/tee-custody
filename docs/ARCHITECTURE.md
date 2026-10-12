# Architecture

## Purpose and context

`teecustody` provides Python workload and TypeScript client libraries for a host application that needs independently verified workload attestation, an authenticated forward-secret channel, split-key custody, and encrypted per-client records. `teecustody-sim` supplies a credential-free launcher, issuer, and local adapters for development and CI. Production workload execution is Google Cloud Confidential Space; the TEE initiates no inbound connections and obtains work by queue pull.

The five increments in `docs/REQUIREMENTS.md` are the approved scope and order. The project baseline question recorded there is treated as answered for this design: use that INC-1 through INC-5 sequence. Do not add capabilities beyond those requirements.

The normative security architecture named by `framework.yaml` controls all security details. In particular it is authoritative for token claims and encodings, key derivation, cryptographic parameter choices, wire schemas, and recovery protocol details. This document does not redefine those values. Implementations and tests must bind every normative invariant to an acceptance or security test; an unresolved conflict is a stop-and-escalate condition, never a local relaxation.

## Requirement traceability

| Requirement | Owning component(s) | Design evidence |
|---|---|---|
| FR-1 | Python Workload; Launcher port; Simulator Launcher | Workload obtains and refreshes launcher tokens using its public-identity-key hash as nonce; no inbound listener. |
| FR-2 | TypeScript Core Attestation Verifier | Explicit trust profile and independent, fail-closed checks for claims, signer, nonce, audience, digest, and validity. JWS handling is pinned to RS256 over the `Crypto` capability (ADR 0009). |
| FR-3 | Simulator; Vector CLI; Python and TypeScript test adapters | Local socket launcher; loopback OIDC discovery and JWKS with Google's CORS behaviour (JWKS yes, discovery no) and an "attacker" JWKS path (ADR 0012); configured signers; negative tokens; shared vectors. |
| FR-4 | TypeScript Core Channel; Python Workload Channel | Normative signed pre-key bundles, HPKE Base mode, exported session keys, authenticated sequence framing, replay rejection. |
| FR-5 | Queue port/adapters; Reference Gateway; Web Transport | Publish/pull queue contract, correlation/routing IDs, browser-facing relay; workload remains pull-only. |
| FR-6 | Web Vault Adapter | WebAuthn PRF-derived wrapping key, encrypted-only IndexedDB value, fail-closed capability checks. |
| FR-7 | Python Enrollment Service; Directory port; Host Enrollment Hook | Library-minted opaque client ID, public identity and fingerprint publication, hook invocation; server trusts authenticated identity and Directory mapping, not request assertions. |
| FR-8 | Python Workload Dispatcher; Session Context; Record Service | Registered host operations and constrained context; reserved built-in names; filtered logger and no secret-bearing context access. |
| FR-9 | Python Custody and Record Services; KeyWrapper, ShareStore, RecordStore ports | 2-of-2 server-share custody, key checks and epochs, transient server-key reconstruction, envelope-encrypted records. |
| FR-10 | Adapter implementations; Workload Assembly | Explicit Launcher, Queue, KeyWrapper, ShareStore, RecordStore, Directory, TrusteeStore, and Notifier ports with production and simulator adapters. SR-6 adds a ninth port, `AuditSink` (`GcsAuditSink`, `InMemoryAuditSink`), which is injected like the others. |
| FR-11 | Python Trustee Service; TrusteeStore; Recovery Service | Threshold validation, sealed shares and commitments, pending-recovery-gated per-trustee release. |
| FR-12 | Python Recovery Service; Client Recovery API; TrusteeStore; Notifier | Pending lifecycle, threshold validation, cancellation/expiry, completion and re-sealing; `recover_start` notifies the owner's existing client(s) and the trustees and is bounded per owner (see "Enrollment, custody, records, and recovery"). |
| FR-13 | Python Custody/Rotation Service; ShareStore; KeyWrapper; Notifier | Epoch/key-ID transition, superseded share handling, rejection notification without secret logging. |
| FR-14 | `examples/notes-app`; Simulator and production assembly | One-command simulator workflow and documented Confidential Space setup, exercising enrollment and persisted note read/write across sessions. |
| FR-15 | Web Profile Build Tool; Production Build Check | Generate module from `trust-profile.json`; reject development anchors in production output; `teecustody-profile check-discovery` binds the pinned `jwks_uri` to Google's discovery document at build time (ADR 0012, D-043). |
| FR-16 | Host Integration README; Notes Example | A second host can follow documented contracts/configuration without implementing cryptography or reading the normative security specification. |
| NFR-1 | All components; test and release traceability | Normative invariant-to-test mapping is mandatory; no unresolved GAP at release. |
| NFR-2 | Python Workload; Queue adapters | Outbound-only cloud access and queue pull; no workload HTTP server. |
| NFR-3 | Secret wrapper and all security-sensitive services | Never persist per-client server keys; redact and minimize secrets; explicit wiping where specified, documenting runtime zeroization limits. |
| NFR-4 | Crypto adapters and dependency manifests | RFC 9180 Base only; approved audited implementations; exact version/hash pins; no hand-rolled key agreement, KDF, or primitives. |
| NFR-5 | TypeScript Core; build configuration | Independent verification always enabled; no skip-verification flag or bypass build. |
| NFR-6 | Package graph; TypeScript Core | Simulator is not a runtime dependency of libraries; Core accepts platform capabilities through interfaces and has no DOM, `fetch`, or storage dependency. |
| NFR-7 | Python and TypeScript Wire adapters; Vector CLI | Canonical CBOR per `spec/wire` (ADR 0002 amendment); both implementations consume and emit the same vectors and a differential corpus; `proto` and vectors change atomically with wire changes. The TypeScript codec is project-owned (ADR 0010). |
| NFR-8 | Python and TypeScript logging adapters | Structured logs limited to the configured allow-list; never log payloads, keys, shares, nonces, ciphertext, or request bodies. |
| NFR-9 | All packages | Configured Python 3.12+/Ruff/strict mypy and TypeScript 5+/ESLint/Prettier/strict TypeScript checks; no `any`. |
| NFR-10 | CI, test suites, review gates | At least 80% new-code line coverage; 100% security-path coverage and a negative test per attestation branch; High/Critical risk blocks absent human acceptance. |
| NFR-11 | CI and release pipeline | Every change runs simulator-only full tests; scheduled/pre-release Confidential Space smoke; from INC-3 each increment runs its real-environment smoke. From INC-2 a scheduled `discovery-binding` job re-checks the pinned Google `jwks_uri` and its CORS header (ADR 0012). |
| NFR-12 | Workload image pipeline | Pinned, reproducible independent image builds and verifiable release signature. |
| NFR-13 | Release pipeline and traceability | All eleven normative deliverables, complete no-GAP traceability, working example/docs, and pre-merge security approval gate v1.0.0. |
| SR-1 | TypeScript verifier; authenticated workload dispatcher; production adapters; Reference Gateway | Client independently verifies workload identity; workload authorizes only authenticated protocol identities; production adapters authenticate workload identity; gateway remains unauthenticated and treats route IDs as hints only. |
| SR-2 | Workload authorization policy; scoped backend adapters; host handlers; Recovery Service; Notifier | Library policy checks authenticated principal and library-owned operation/resource constraints; adapters scope each access to the authorized tenant; host application authorization remains host-owned. `recover_start`'s `owner_id` is a subject, never a principal; owner and trustees are notified; `recovery_id` never authorizes anything on its own (ADR 0004 amendment). |
| SR-3 | Every parser, adapter, simulator, CLI, configuration loader, host hook, and browser adapter | Strict typed/schema validation, canonical wire checks, and finite limits apply before domain use, state mutation, or expensive work. |
| SR-4 | Reference Gateway; workload queue/operation ingress; simulator; Recovery Service; Workload Audit and Alert Emitter | Configured finite rate, concurrency, payload, polling, queue-batch, retry, and expensive-operation budgets bound resource use. Per-owner pending-recovery and start-rate bounds; pre-principal audit/alert records are aggregated and capped per interval. |
| SR-5 | Web transport; production adapters; storage adapters | Production network calls require authenticated encrypted transport and expected service identity; protected data-at-rest formats remain unchanged. |
| SR-6 | Workload Audit and Alert Emitter; `AuditSink` port (`GcsAuditSink`, `InMemoryAuditSink`); Audit Project; platform audit sink; Release Tooling | Create-if-absent, retention-locked workload audit objects in a bucket in a separate audit project; per-interval aggregates for pre-principal failures; operator actions attributed by IAM principal through Cloud Audit Logs exported by an aggregated sink that workload-project administrators cannot modify; release sign-offs recorded in the same protected storage. Records carry role-qualified `actor_client_id`, `subject_client_id` and `recovery_id` (D-007). `recovery_id` is never an authorization input. Aggregate `count` is pending H-2 (ADR 0005 amendments). |
| SR-7 | Workload assembly; Cloud KMS; simulator and release configuration | Runtime secrets use existing platform identity and Cloud KMS operations; development signer material is isolated; provisioning, rotation, and revocation are controlled without a new secret service. |
| SR-8 | Workload and production adapter identities; release process | Each identity receives only the existing service permissions required for its role; CI has no release-signing key access. |
| SR-9 | Dependency manifests and CI | Configured dependency admission, exact crypto pins, and scanners remain mandatory. |
| SR-10 | Release Tooling (build recipe, signer reproduction procedure, deploy/publish verification); workload image and client package publication | Each of ≥ `SIGNERS_REQUIRED` independent signers rebuilds the artifact from the approved commit outside CI and signs only on digest match; the signed verification record states the reproduced digest; deploy/publish require matching records and signatures from distinct identities (ADR 0006 amendment). |
| SR-11 | All public and adapter error boundaries | Stable sanitized error categories are returned; provider details and secret-bearing causes remain internal and unlogged. |
| SR-12 | Workload Audit and Alert Emitter (`alert/` records via `AuditSink`); Audit Project log-based alert policies; TypeScript Core `SecurityEventSink`; `@teecustody/web` `BeaconSecurityEventSink`; notes-app security-event route | One designed path per spec §12 alert: WIP-denied decrypt and `alert/` object creation are alerted from the platform audit sink; `kcv` mismatch and trustee-share rejection are distinct alert-class workload outcome codes; debug-mode tokens are reported by Core through an injected sink carrying a reason code only (ADR 0007). |
| SR-13 | `@teecustody/core` and `@teecustody/web` lint/build rules; `teecustody-profile` `manifest`, `csp`, `check-html` subcommands; notes-app static host; Host Integration README | Strict CSP compatibility of library code; SRI on every script; hash-only `script-src`; no third-party scripts on key pages; reproducible web build with a published, signer-reproduced hash manifest; README states the residual origin-trust limit (ADR 0008). |

## Components and dependency direction

Dependencies point toward domain/application contracts. Domain services do not import cloud SDKs, web APIs, simulator code, or transport implementations.

| Component | Responsibility and allowed dependencies |
|---|---|
| TypeScript `teecustody-core` | Platform-neutral protocol/domain client: trust-profile verification, canonical wire values, session/channel and client-side custody/recovery flows. Depends on explicit capability interfaces and approved crypto APIs only; no DOM, `fetch`, or persistence. |
| TypeScript `teecustody-web` | Browser adapters: WebAuthn PRF, IndexedDB ciphertext persistence, web transport, profile module generation/check. Depends on Core and browser capabilities, not the simulator at runtime. |
| Python `teecustody` | Workload domain and application services: attestation lifecycle, dispatch/session context, custody, records, recovery, and ports. No inbound server framework. Depends on port protocols and approved cryptographic libraries. |
| Python `teecustody-sim` | Development/test-only launcher socket, OIDC issuer, local/in-memory adapters, token/vector tools, and simulator orchestration. May depend on test/runtime libraries; production libraries and client packages must not depend on it. |
| Reference Gateway | FastAPI example adapter that relays browser requests and responses through Queue. It is not the workload and has no authority to assert attestation or client identity. |
| Production adapters | Google Cloud implementations for Confidential Space launcher access, Pub/Sub queue, Cloud KMS, Firestore/GCS, Directory, TrusteeStore, and Notifier as configured by the host. |
| Notes application and image pipeline | Demonstrate the supported host workflow; build, reproduce, and sign the workload image at release. The notes-app static host serves the web client with the generated CSP header and exposes the example `POST /security-events` route (see "Security alerting"). |
| Workload Audit and Alert Emitter | Application service in `teecustody`. Builds allow-listed audit records only from authorized context. Classifies alert outcome codes. Aggregates and caps pre-principal events per interval. Writes only through the `AuditSink` port and never imports a cloud SDK. |
| Audit Project (infrastructure) | A GCP project separate from the workload project. No workload- or gateway-project principal holds admin there; the permitted cross-project grants are exactly those in SR-8. It holds the workload audit bucket, the `platform-audit` log bucket that receives the aggregated audit-log sink, and the log-based alert policies. It is deployment configuration, not a dependency of any package. |
| Release Tooling (`release/`) | Build recipe, signer reproduce-and-sign procedure, verification-record format, and the deploy/publish verification check. CI runs the build only and produces unsigned output. Signers run reproduce-and-sign on their own workstations. |
| Web Delivery Tooling | The `teecustody-profile` subcommands in `@teecustody/web`: `check-discovery` (INC-2; ADR 0012) and `manifest`, `csp`, `check-html` (INC-3). `check-discovery` verifies the trust profile's pinned `jwks_uri` against the issuer's discovery document. The other three produce the bundle hash manifest and the CSP header value, and check SRI and third-party scripts. The notes-app and host builds use them. |

The TypeScript core and Python workload share only the normative protocol/wire contract and generated vectors. They do not call one another. Browser and gateway traffic is relayed through a queue; the workload pulls messages and publishes responses.

## Contracts

All byte strings below are opaque `bytes`/`Uint8Array` unless a normative schema defines a more specific representation. No contract may serialize secret values into errors or logs. The normative security architecture and canonical CDDL remain authoritative for cryptographic encodings and on-wire field names. Contract error codes below are stable API categories; internal causes are not returned to an untrusted peer.

### Attestation and launcher

Python port:

```text
Launcher.get_attestation_token(
    audience: str,
    token_type: str,
    identity_nonce: bytes
) -> AttestationToken
LauncherError = UNAVAILABLE | INVALID_CONFIGURATION | TOKEN_REJECTED
```

`identity_nonce` is `SHA-256` of the raw 32-byte Ed25519 identity public key (RFC 8032 encoding), which is spec §5.1 step 2's `H(IK_pub)`: 32 bytes. The launcher request carries it as one nonce string, its lowercase hex encoding (64 ASCII characters). The client compares `eat_nonce` against that same string (CI-7). The workload requests exactly one nonce. The client accepts `eat_nonce` in only two shapes: a string equal to that value, or an array of length 1 whose only element equals it. Anything else is `CLAIM_MISMATCH`. This covers both shapes that V-01 found possible, because F-05 is not documented. The 64-character value fits both of the conflicting documented length bounds in F-03 (10–74 and 8–88). `AttestationToken` is an opaque signed-token string plus locally parsed `issued_at` and `expires_at` metadata; parsed claims are untrusted until client verification. Startup fails if a token cannot be obtained. Refresh occurs before expiry using the normative/configured refresh parameters; refresh failure does not replace a still-valid token with an unverified token. The launcher adapter opens only the platform-provided socket and does not bind a listener.

Simulator HTTP/OIDC surface (loopback by default, spec §15.5):
- `GET /.well-known/openid-configuration` returns `issuer` (`SIM_ISSUER`), `jwks_uri`, and signing metadata, which is `RS256` only. Like Google's discovery endpoint, it sends **no** CORS header (CI-2-1). Clients never fetch it. Only `teecustody-profile check-discovery` and simulator tests read it (ADR 0012).
- `GET /jwks` returns only the public half of the simulator's **token-signing (issuer) key** (CI-8), with `Access-Control-Allow-Origin` as Google sends it; `OPTIONS` is answered as a CORS preflight. Development image-signer public keys are never served by the issuer. They reach the client only through the development trust profile's `signer_keys`.
- `GET /attacker/jwks` serves, with the same headers, the public half of a separate simulator "attacker" key under two `kid`s: its own, and the issuer's. It exists so that T-29 (JWKS path substitution on a shared origin) can be tested end to end. No profile can name it (ADR 0012; INC-2-API §16.3).
- The local launcher socket returns signed tokens.
- **Development signers** (spec §15.2 item 3; D-016). There are `SIGNERS_REQUIRED` of them, and each has a single F-11 algorithm (default `RSASSA_PSS_SHA256`). For each signer, the token's `submods.container.image_signatures` carries one entry `{key_id, signature, signature_algorithm}`:
  - `key_id` is the lowercase hex SHA-256 of that signer's SPKI DER, the same value the development profile carries.
  - `signature_algorithm` is the signer's algorithm.
  - `signature` is the padded standard base64 of a real signature made with that key over simulator-chosen payload bytes. The payload format is simulator-internal and non-normative, and no client reads it.

  The unknown signer's entry uses its own `key_id`. `teecustody-sim profile` computes `key_id` from the same SPKI DER the simulator used.
- `teecustody-sim serve` runs the issuer and launcher socket without a container, for host-process workloads and credential-free tests (CI-6). `teecustody-sim up` also runs the workload image with the launcher directory mounted.

`SIGNERS_REQUIRED` is enforced before startup. Signer private keys stay in simulator configuration and are never emitted by the CLI, issuer responses, logs, or vectors. The simulator supports named negative alterations/omissions for required checks and vector output to an explicit destination directory. Development keys are never accepted by a production trust profile.

TypeScript verifier:

```text
verifyAttestation(
    token: string,
    profile: TrustProfile,
    expected: ExpectedAttestation,
    events: SecurityEventSink,
    deps: VerifierDeps
) -> Promise<VerifiedAttestation>

VerifierDeps   = { crypto: Pick<Crypto, "sha256" | "verifySignature">, fetcher: Fetcher,
                   now: () => number /* Unix ms */, limits: VerifierLimits }
VerifierLimits = { maxTokenBytes, maxJwksBytes, maxDiscoveryBytes? }   // positive safe integers;
                 // maxDiscoveryBytes is deprecated and ignored since D-043 (validated if present; removed before v1.0.0)
```

`deps` supplies every platform capability the checks need (CI-1). The verifier holds no state and does no caching. Compact-JWS parsing, header strictness, retrieval of the pinned `jwks_uri` and key selection follow ADR 0009 as amended by ADR 0012. **No client fetches an OIDC discovery document at runtime** (D-043 constraint-deviation of spec §6.1). The discovery binding is checked at build time and on a schedule (see "Web code delivery" and ADR 0012).

`events` is required, not optional. Debug-mode reporting (SR-12, spec §6.6, §12 line 303) works like this. Once the signature check (§6.1) and the issuer check (§6.2) have both passed under `profile`, Core calls `events.report({ code: "ATTESTATION_DEBUG_MODE", at })` exactly once for that call if `dbgstat` is present and differs from the required value. This happens whatever the outcome of the other checks. Core does not await the report for the verification decision, and it catches and discards a rejected report. The token is still rejected with `CLAIM_MISMATCH`; the error contract below is unchanged. A token that fails signature or issuer verification never triggers a report, so forged tokens cannot raise alerts. The event carries no token content, claims, instance ID or key material.

**`TrustProfile`** (CI-4; **version 2** since D-043 / ADR 0012). The JSON form is in `docs/INC-2-API.md` §16.1, which supersedes `docs/tasks/INC-1/API.md` §E. It contains exactly the following fields:
- `profile_version` (2), `profile_kind` (`production` | `development`) and `token_type` (`OIDC` only);
- `issuer`, `jwks_uri` (exact, canonical, pinned) and `expected_audience`;
- `token_max_age_s` (spec §14 `TOKEN_MAX_AGE`);
- `allowed_hwmodels` and `allowed_digests`;
- `signer_keys` (`{key_id, algorithm}`; see "Image check" below) and `signers_required` (1 ≤ n ≤ number of signer keys);
- `expected_args_hash` and `expected_env_hash`.

Only `parseTrustProfile` creates a profile. It rejects any `profile_version` other than 2 first, then unknown keys at every level, so a v1 profile with `discovery_url`/`jwks_origin` is always rejected. `profile_kind` does one thing: it selects which anchor shapes `parseTrustProfile` accepts.
- Production requires:
  - the Google issuer;
  - `jwks_uri` exactly `https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com` (FACTS F-07, verified 2026-09-30). It is a Core constant, compared by string equality;
  - `allowed_hwmodels` drawn from the F-09 documented values, never including `GCP_SHIELDED_VM`, which is not confidential hardware (spec §2).
- Development requires a non-Google `https:` issuer and a canonical loopback `jwks_uri` (`http:` allowed) whose path is exactly `/jwks`.
- The JWKS origin, where a consumer needs it (CSP `connect-src`), is derived as `new URL(jwks_uri).origin` and is never stored. No profile names a discovery URL. The build tool takes the discovery URL as an input: a fixed constant for production, an argument for development (ADR 0012).

No §6 check function reads `profile_kind`, so the check sequence is identical under both profiles (spec §6 preamble, §15.4, I13).

The two hashes are defined as follows:
- `expected_args_hash` is the lowercase hex SHA-256 of the canonical CBOR encoding of `submods.container.args`, as an array of text strings in token order.
- `expected_env_hash` is the same over `submods.container.env`, as a map from text to text.

**Image check (spec §6.8 as decided by D-016, a human constraint-deviation).** The token does not carry the signed payload (FACTS F-12), so the client cannot re-verify signature bytes. The Google attestation service verifies image signatures before it signs the token. The client independently requires that the token name enough of the client's own embedded signers.

**Signer entry.** Each `signer_keys` entry is exactly `{ key_id, algorithm }`:
- `key_id` is the signer fingerprint: lowercase hex SHA-256 of the signer public key's DER SubjectPublicKeyInfo (F-11), 64 characters, unique within the profile.
- `algorithm` is the one algorithm that signer uses. It is one of `RSASSA_PSS_SHA256`, `RSASSA_PKCS1V15_SHA256` or `ECDSA_P256_SHA256` (F-11).

The profile carries no public-key bytes. Profile generators (`teecustody-sim profile`, the `teecustody-profile` host tooling) take each signer's SPKI DER as input and compute `key_id` from it. They never copy a `key_id` from input.

**`checkImage(token, profile) -> signerKeyIds`**. The check is synchronous and needs no crypto or network. Every failure is `AttestationError(code, "image")`. Steps, in order:
1. `submods.container.image_digest`:
   - absent → `CLAIM_MISSING`;
   - not a string in `allowed_digests` (exact match) → `CLAIM_MISMATCH`.
2. `submods.container.image_signatures`:
   - absent → `CLAIM_MISSING`;
   - not an array → `CLAIM_MISMATCH`.
3. An entry **counts** only if all of the following hold:
   - it is an object;
   - its `key_id` is a string exactly equal (case-sensitive) to a profile `key_id`;
   - its `signature_algorithm` is a string equal to that profile entry's `algorithm`;
   - its `signature` is a non-empty string.

   Entries that do not count are ignored: unknown signers, malformed entries and algorithm mismatches. Duplicate `key_id`s count once.
4. Fewer than `signers_required` distinct counted `key_id`s → `UNTRUSTED_SIGNER`.
5. Otherwise, return the distinct counted `key_id`s sorted ascending. They become `VerifiedAttestation.signerKeyIds`.

The `signature` bytes are not decoded or verified by the client (D-016).

**`ExpectedAttestation`** is `{ identityNonce }` (32 bytes) only (CI-9, amended). The workload-digest binding in spec §5.2 step 5 is not an input to `verifyAttestation`. Instead, INC-2 bundle verification compares the `image_digest` under each pre-key signature with `VerifiedAttestation.imageDigest`. That value has already been checked against the allow-list.

**`VerifiedAttestation`** can be constructed only on success. It contains `issuer`, `audience`, `imageDigest`, `signerKeyIds` (sorted ascending), `hwmodel`, `issuedAtMs` and `expiresAtMs`.

Each required predicate has an independently testable check. Any failed or missing check rejects the whole token. There is no verification bypass.

**`AttestationError`** is `{ code, check }` (CI-5):
- `code` is one of `MALFORMED`, `UNTRUSTED_SIGNER`, `CLAIM_MISSING`, `CLAIM_MISMATCH`, `NOT_YET_VALID`, `EXPIRED` or `UNSUPPORTED_ALGORITHM`.
- `check` is the failing check's ID: `profile`, `token`, `signature`, `issuer`, `audience`, `time`, `nonce`, `platform`, `support_attributes`, `image` or `launch_config`.
- The message is exactly `"<check>: <code>"`, and the error exposes no token contents.

### Wire and vectors

Both implementations consume and produce canonical CBOR conforming to the normative CDDL. The protocol identifier is the normative `proto` value. The simulator vector command takes `--out <path>` and writes the same named cases and expected canonical bytes consumed by Python and TypeScript tests; negative vector identifiers identify the single altered/omitted check without embedding signing secrets. A wire change requires, in the same change, updated CDDL, `proto`, generated vectors, and both implementation tests. Vector mismatch is a hard test failure; no permissive decoder fallback is allowed.

**Wire binding (CI-3; ADR 0002 amendment).** `spec/wire` is authored in this repository from the normative spec. Every change to it is human-gated (`escalation.always_human`).
- `proto` is `"tee-chan-v1"`, from spec §5.3 step 8.
- Canonical CBOR is RFC 8949 §4.2.1 Core Deterministic Encoding. Only these types are permitted: integers in [−2^64, 2^64−1], byte strings, UTF-8 text strings, arrays, maps with text keys only, `false`, `true` and `null`. Tags, floats, `undefined`, other simple values and indefinite lengths are forbidden. Duplicate keys and trailing bytes are also forbidden.
- Decoders check the input length before parsing, enforce depth and item limits, and require re-encoding to reproduce the input exactly.

INC-1 authors the canonical rules, `proto`, and the vector-suite CDDL. Protocol-message CDDL (bundle, envelopes, share records) is authored in the increment that first uses it, under the same gate.

**Codecs.**
- Python uses a project-owned structural pre-scan followed by `cbor2` (T-04).
- TypeScript uses a project-owned strict codec with no dependency (ADR 0010). It is the single CBOR entry point in Core and Web.
- Both codecs pass the same shared vectors and a differential corpus generated by the simulator.

### Queue and gateway

The workload publishes signed pre-key bundles and responses to the Queue; it pulls requests and never accepts inbound connections. `SignedPreKeyBundle` and `CanonicalEnvelope` use the normative security architecture and CDDL without gateway-defined fields. The gateway and browser transport relay opaque signed bundles and envelopes; they do not establish trust, authorize clients, or treat a client-asserted identity as authoritative.

Language-neutral Queue port:

```text
publish_bundle(instance: InstanceId, bundle: SignedPreKeyBundle) -> None
list_bundles() -> list[PublishedBundle]
publish_request(instance: InstanceId, request_id: RequestId, body: CanonicalEnvelope) -> MessageId
pull_requests(instance: InstanceId, max_messages: int, wait: Duration) -> list[QueueMessage]
ack(message_id: MessageId) -> None
publish_response(client_id: ClientId, request_id: RequestId, body: CanonicalEnvelope) -> None
pull_responses(client_id: ClientId, after: ResponseCursor | None) -> ResponsePage
```

`PublishedBundle` contains the instance identifier and the signed bundle. `ResponsePage` contains zero or more responses and the cursor to use as `after` on the next poll. `request_id` is opaque correlation metadata and is preserved from gateway publication through the workload response; it does not replace authenticated session framing. Queue delivery may repeat. The workload authenticates and checks sequence/replay before dispatch, and acknowledges only after accepting or permanently rejecting a request. `max_messages` must be positive and bounded by adapter configuration. Queue errors are `INVALID_ARGUMENT`, `NOT_FOUND`, `CONFLICT`, `UNAVAILABLE`, or `INTERNAL`; no message body is included in error text or logs.

The Reference Gateway exposes exactly these routes:

| Route | Contract |
|---|---|
| `GET /bundles` | Returns `200` with the currently published `PublishedBundle` entries. A client selects the target instance and verifies the bundle signature, workload binding, validity, and pre-key status locally against the normative protocol before opening a session. |
| `POST /requests/{instance}` | Accepts a canonical request envelope, publishes it for that instance, and returns `202` with its `request_id`. The gateway does not infer an authoritative client identity from request metadata. |
| `GET /responses/{client}?after=` | Returns `200` with a `ResponsePage` for that client after the supplied opaque cursor; an empty page is a successful poll with no available response. The caller sends the returned cursor on its next poll. |

`FetchTransport` implements those three operations using the same paths and semantics; it rejects malformed success responses rather than passing them to protocol code. Gateway errors have the stable JSON shape `{"code":"<ERROR_CODE>"}`: `400 INVALID_ARGUMENT` for malformed/oversized input or an invalid cursor, `404 UNKNOWN_INSTANCE` or `UNKNOWN_CLIENT` for unknown route identifiers, `503 UNAVAILABLE` for queue/backend unavailability, and `500 INTERNAL` for other internal failures. FetchTransport maps these to stable transport categories `INVALID_ARGUMENT`, `NOT_FOUND`, `UNAVAILABLE`, or `INVALID_RESPONSE`; network failures map to `UNAVAILABLE`. No error includes message bodies, envelope contents, tokens, or internal causes. The gateway validates only transport framing and configured size limits; cryptographic verification, identity resolution, and authorization remain in the client/workload.

### TypeScript Core capability contracts

The Core owns these platform-neutral contracts; adapters supply implementations. All operations are asynchronous and use `Uint8Array` for opaque bytes. Adapters reject with `CapabilityError`; provider-specific exceptions and causes never escape, and messages/logs contain no credentials, payloads, or secret bytes. The Core uses no DOM, `fetch`, or storage APIs.

```ts
type Bytes = Uint8Array;
type InstanceId = string;
type ClientId = string;
type RequestId = string;
type ResponseCursor = string;
type SignedPreKeyBundle = Bytes;
type CanonicalEnvelope = Bytes;
type ClientShare = Bytes; // cs: exactly 32 bytes

type CapabilityErrorCode =
    | "INVALID_ARGUMENT"
    | "NOT_FOUND"
    | "UNAVAILABLE"
    | "INVALID_RESPONSE"
    | "UNSUPPORTED"
    | "USER_PRESENCE_REQUIRED"
    | "AUTHENTICATION_FAILED"
    | "HTTP_ERROR"
    | "UNSUPPORTED_ALGORITHM"
    | "INTERNAL";

class CapabilityError extends Error {
    constructor(readonly code: CapabilityErrorCode) {
        super(code);
    }
}

interface PublishedBundle {
    readonly instanceId: InstanceId;
    readonly bundle: SignedPreKeyBundle;
}

interface PublishedResponse {
    readonly requestId: RequestId;
    readonly body: CanonicalEnvelope;
}

interface ResponsePage {
    readonly responses: readonly PublishedResponse[];
    readonly next: ResponseCursor | undefined;
}

interface Transport {
    listBundles(): Promise<readonly PublishedBundle[]>;
    postRequest(instance: InstanceId, body: CanonicalEnvelope): Promise<RequestId>;
    getResponses(client: ClientId, after?: ResponseCursor): Promise<ResponsePage>;
}

interface ShareVault {
    get(client: ClientId): Promise<ClientShare | undefined>;
    set(client: ClientId, share: ClientShare): Promise<void>;
    clear(client: ClientId): Promise<void>;
}

interface FetchResponse {
    readonly status: number;
    readonly body: Bytes;
}

interface Fetcher {
    get(url: string): Promise<FetchResponse>;
}

interface HpkeSenderContext {
    readonly encapsulatedKey: Bytes;
    seal(aad: Bytes, plaintext: Bytes): Promise<Bytes>;
    export(label: Bytes, length: number): Promise<Bytes>;
    destroy(): void;
}

interface HpkeReceiverContext {
    open(aad: Bytes, ciphertext: Bytes): Promise<Bytes>;
    export(label: Bytes, length: number): Promise<Bytes>;
    destroy(): void;
}

type SignatureAlgorithm = "RSASSA_PKCS1V15_SHA256"; // JWS RS256 only (ADR 0009; D-016 removed image-signature use)

interface RsaPublicJwk {
    readonly kty: "RSA";
    readonly n: string;
    readonly e: string;
}

type PublicKeyInput = { readonly format: "jwk"; readonly jwk: RsaPublicJwk };

type SecurityEventCode = "ATTESTATION_DEBUG_MODE";

interface SecurityEvent {
    readonly code: SecurityEventCode;
    readonly at: number; // Unix epoch milliseconds, client clock
}

interface SecurityEventSink {
    report(event: SecurityEvent): Promise<void>;
}

interface Crypto {
    randomBytes(length: number): Bytes;
    sha256(data: Bytes): Promise<Bytes>;
    verifyEd25519(publicKey: Bytes, data: Bytes, signature: Bytes): Promise<boolean>;
    verifySignature(algorithm: SignatureAlgorithm, key: PublicKeyInput, data: Bytes, signature: Bytes): Promise<boolean>;
    setupHpkeSender(recipientPublicKey: Bytes, info: Bytes): Promise<HpkeSenderContext>;
    setupHpkeReceiver(recipientPrivateKey: Bytes, encapsulatedKey: Bytes, info: Bytes): Promise<HpkeReceiverContext>;
    aes256GcmEncrypt(key: Bytes, nonce: Bytes, aad: Bytes, plaintext: Bytes): Promise<Bytes>;
    aes256GcmDecrypt(key: Bytes, nonce: Bytes, aad: Bytes, ciphertext: Bytes): Promise<Bytes>;
}
```

`Transport` maps `listBundles` to `GET /bundles`, `postRequest` to `POST /requests/{instance}`, and `getResponses` to `GET /responses/{client}?after=`; it encodes path/query values as URL components and omits `after` when undefined. `postRequest` returns the gateway's `request_id`. An empty response page is success. Malformed successful bodies reject with `INVALID_RESPONSE`; gateway `INVALID_ARGUMENT` maps to `INVALID_ARGUMENT`, unknown route IDs map to `NOT_FOUND`, and gateway/network unavailability maps to `UNAVAILABLE`. Other gateway failures map to `INTERNAL`.

`ShareVault` scopes each value by `client`. `get` returns `undefined` only when no share is stored; otherwise it returns the 32-byte share after user presence is confirmed. `set` requires user presence, stores no plaintext, and does not retain the caller's mutable buffer. `clear` removes the scoped value and is idempotent when absent. Missing user presence rejects with `USER_PRESENCE_REQUIRED`; unavailable or unsupported protected storage rejects with `UNAVAILABLE` or `UNSUPPORTED`; invalid share length rejects with `INVALID_ARGUMENT`; authentication/decryption failure rejects with `AUTHENTICATION_FAILED`. No operation falls back to weaker storage.

`Fetcher.get` performs HTTPS GET only, with one exception: an adapter may also permit `http:` to the loopback hosts `127.0.0.1`, `[::1]` and `localhost`. Core requests such a URL only under a development profile, because `parseTrustProfile` rejects anything but the exact Google `jwks_uri` in production profiles (ADR 0009 rule 9, ADR 0012). Core passes exactly the trust profile's pinned `jwks_uri` and never a discovery URL. The adapter follows no redirect at all (D2-14) and sends no request header beyond what the platform adds, so the browser request stays a CORS "simple" request with no preflight. It returns the HTTP status and raw response bytes without interpreting JSON. Invalid URLs reject with `INVALID_ARGUMENT`, network failures with `UNAVAILABLE`, and non-success HTTP statuses with `HTTP_ERROR`; malformed successful JWKS data is rejected by the Core (`UNTRUSTED_SIGNER`, ADR 0009 rule 3).

`SecurityEventSink` is supplied by the host through `TeeClient` configuration `{ trustProfile, transport, vault, securityEvents, crypto, fetcher }` (INC-2). All six are required. Core passes `securityEvents` to every `verifyAttestation` call, and builds `VerifierDeps` from `crypto`, `fetcher`, the platform clock and Core's documented default `VerifierLimits` (CI-1). `report` must not throw synchronously. It may reject with `CapabilityError` (`UNAVAILABLE`, `INTERNAL`), and Core ignores the rejection. Implementations send only `code` and `at`, and never block or alter protocol decisions. `@teecustody/web` provides `BeaconSecurityEventSink(endpoint: string)`. It requires a same-origin `https` endpoint, or a loopback endpoint under the development profile only. It POSTs `{"code":"<code>"}`, sends at most one report per code per 60 s per page, and swallows transport failures. A Node or test sink records events in memory.

`Crypto` delegates to approved platform cryptography or maintained audited libraries; it does not implement primitives itself. HPKE setup uses RFC 9180 Base mode with the normative suite; `export` is performed on the same context as `seal`/`open`, and contexts are destroyed after use. Core supplies normative labels and the required 32-byte export length. AES-GCM uses the normative 256-bit keys and 96-bit nonces. Invalid lengths/inputs reject with `INVALID_ARGUMENT`, unavailable functionality with `UNSUPPORTED` or `UNAVAILABLE`, unsupported suites with `UNSUPPORTED_ALGORITHM`, and authentication failure rejects with `AUTHENTICATION_FAILED`; signature mismatch returns `false`. Context destruction is idempotent.

`verifySignature` (CI-2) exists only for the attestation-token JWS (`RS256`, ADR 0009). It supports exactly one algorithm, `RSASSA_PKCS1V15_SHA256`, with an RSA public JWK. Image signatures are never verified client-side (D-016), so no other algorithm or key format is needed.

It is implemented with WebCrypto or Node `crypto` only. It resolves `false` when the signature does not match. It rejects in these cases:
- `INVALID_ARGUMENT` for an unparseable key or an RSA modulus under 2048 bits. The modulus length is read from the imported key, and no ASN.1 is parsed in project code.
- `UNSUPPORTED_ALGORITHM` for any other algorithm.

Implementations must not expose provider-specific errors or log inputs.

### Workload operations and session context

```text
register_operation(name: OperationName, handler: Handler) -> None
Handler(context: SessionContext, payload: CanonicalValue) -> CanonicalValue
SessionContext.client_id: ClientId
SessionContext.session_id: SessionId
SessionContext.records: RecordOperations
SessionContext.logger: AllowListedLogger
RecordOperations.put(record_id: RecordId, value: bytes) -> None
RecordOperations.get(record_id: RecordId) -> bytes | None
RecordOperations.delete(record_id: RecordId) -> None
RecordOperations.list(prefix: str | None, limit: int) -> list[RecordId]
```

`SessionContext` exposes no key, share, DEK, nonce, or session-key getter. Built-in custody/recovery operation names are reserved: `enroll`, `open_session`, `close`, `set_trustees`, `release_share`, `recover_start`, `recover_complete`, `recover_cancel` (D-008; spec §8.3 step 4), `rotate_share`, `rotate_sk`. Duplicate, malformed, or reserved registrations fail configuration with `INVALID_OPERATION_REGISTRATION`. Dispatch order is: verify frame/authentication, enforce sequence/replay policy, resolve authenticated client via Directory, authorize built-in/registered operation, then invoke handler. Failures never dispatch the handler and return stable categories `INVALID_FRAME`, `AUTHENTICATION_FAILED`, `REPLAYED_OR_OUT_OF_ORDER`, `UNKNOWN_CLIENT`, `UNKNOWN_OPERATION`, `NOT_AUTHORIZED`, `LIMIT_EXCEEDED`, `RECORD_NOT_FOUND`, `BACKEND_UNAVAILABLE`, or `INTERNAL`; peer-facing errors do not disclose internal causes. `LIMIT_EXCEEDED` is returned before any state mutation when an SR-4 budget or bound is exceeded (ADR 0004).

### Backend ports

The following typed operations are the application boundary. Production and simulator adapters must implement the same semantics; adapter-specific exceptions are translated to the common categories listed below.

| Port | Contract (all methods are workload-side unless noted) | Error semantics |
|---|---|---|
| `Launcher` | `get_attestation_token(audience, token_type, identity_nonce) -> AttestationToken` | `UNAVAILABLE`, `INVALID_CONFIGURATION`, `TOKEN_REJECTED`; see Attestation contract. |
| `Queue` | `publish_request`, `pull_requests`, `ack`, `publish_response`, `pull_responses` as above | `INVALID_ARGUMENT`, `UNAVAILABLE`, `NOT_FOUND`; repeated delivery is permitted. |
| `KeyWrapper` | `wrap(key_id, plaintext_key, aad) -> WrappedKey`; `unwrap(key_id, wrapped_key, aad) -> Secret[bytes]` | `KEY_NOT_FOUND`, `AUTHENTICATION_FAILED`, `UNAVAILABLE`; plaintext exists only transiently in redacted `Secret`. |
| `ShareStore` | `put(client_id, epoch, sealed_share, commitment) -> None`; `get(client_id, epoch) -> SealedShare`; `advance_epoch(client_id, old_epoch, new_epoch) -> None`; `delete_epoch(client_id, epoch) -> None` | `NOT_FOUND`, `CONFLICT`, `UNAVAILABLE`; atomic epoch advance; no unsealed server key stored. |
| `RecordStore` | `put(client_id, record_id, ciphertext, wrapped_dek, nonce, tag, aad, epoch) -> None`; `get(client_id, record_id) -> EncryptedRecord | None`; `delete(client_id, record_id) -> None`; `list(client_id, prefix, limit) -> list[RecordId]` | `INVALID_ARGUMENT`, `NOT_FOUND`, `UNAVAILABLE`; store receives ciphertext and wrapped DEK only. |
| `Directory` | `publish(client_id, identity_public_key, fingerprint) -> None`; `resolve(client_id) -> ClientIdentity`; `resolve_fingerprint(fingerprint) -> ClientId | None` | `CONFLICT`, `NOT_FOUND`, `UNAVAILABLE`; immutable identity binding within an epoch unless normative rotation says otherwise. |
| `TrusteeStore` | `put_sealed(owner_id, trustee_id, epoch, sealed_share, commitment) -> None`; `get_for_pending_recovery(recovery_id, trustee_id) -> SealedShare`; `record_approval/rejection(recovery_id, trustee_id) -> None`; `create_pending_recovery(pending: PendingRecovery, max_pending: int, max_starts: int, window: Duration) -> None`; `get_recovery(recovery_id) -> PendingRecovery`; `transition_recovery(recovery_id, from_state, to_state) -> None` | `NOT_FOUND`, `NOT_AUTHORIZED`, `CONFLICT`, `LIMIT_EXCEEDED`, `UNAVAILABLE`; release only for the matching pending, non-expired recovery and trustee. `create_pending_recovery` atomically rejects with `LIMIT_EXCEEDED` if the owner already has `max_pending` recoveries in state `PENDING` or has started `max_starts` within `window`. Non-secret recovery metadata (`owner_id`, `recovery_id`, `state`, `started_at`) is retained for at least `window` after a terminal state so the start rate can be counted. `transition_recovery` is conditional on `from_state`. |
| `Notifier` | `notify(recipient: ClientId, event: NotificationEvent) -> None` | `INVALID_ARGUMENT`, `UNAVAILABLE`; event contains kind/IDs/timestamps only, never share or secret material. `LogNotifier` logs only `client_id` (recipient) and the event kind as an outcome code, and omits `recovery_id` and `index`. `recovery_id` is permitted only in audit records (D-007), and general logs keep the base allow-list. |
| `AuditSink` | `append(key: AuditKey, record: AuditRecord) -> AppendResult` | `INVALID_ARGUMENT` (field outside the allow-list, or malformed key), `UNAVAILABLE`; never overwrites. See "Protected audit". |

```text
PendingRecovery   = { owner_id, recovery_id, rib_pub, epoch, started_at, expires_at, state }
RecoveryState     = PENDING | COMPLETED | CANCELLED | EXPIRED        # only PENDING is non-terminal
NotificationEvent = RECOVERY_PENDING          { recovery_id, owner_id, started_at, expires_at }   # to the owner
                  | RECOVERY_REVIEW_REQUESTED { recovery_id, owner_id, started_at, expires_at }   # to each trustee
                  | SHARE_REJECTED            { recovery_id, index }                              # to the owner (spec §8.3 step 2)
AuditKey          = { class: EVENT | ALERT | AGGREGATE | RELEASE, id: str }   # id matches ^[A-Za-z0-9_-]{1,128}(/[A-Za-z0-9_-]{1,64}){0,2}$
AuditRecord       = { outcome: OutcomeCode, ts: Timestamp, interval_start?: Timestamp, interval_end?: Timestamp,
                      actor_client_id?, subject_client_id?, recovery_id?,                    # D-007 (H-1)
                      request_id?, session_id?, prekey_id?, epoch?,
                      count?: int >= 0 }                                                    # AGGREGATE class only (D-012)
AppendResult      = CREATED | ALREADY_EXISTS
```

`GcsAuditSink` writes object `<class-lowercase>/<YYYY>/<MM>/<DD>/<id>` in the workload audit bucket of the Audit Project. It serializes the record as JSON with sorted keys, uses the create-if-absent precondition (`ifGenerationMatch=0`), and maps a precondition failure to `ALREADY_EXISTS`. `InMemoryAuditSink` (simulator) has identical semantics and exposes the records it received to tests. Both validate every record against the allow-list before writing.

Shared adapter errors are `INVALID_ARGUMENT`, `NOT_FOUND`, `CONFLICT`, `NOT_AUTHORIZED`, `UNAVAILABLE`, `AUTHENTICATION_FAILED`, and `INTERNAL`. Retries are permitted only for idempotent calls or with the same operation identifier. Secret values and request content are never attached to exceptions or logs.

### Enrollment, custody, records, and recovery

Enrollment accepts a verified session identity public key and host enrollment metadata; it generates a cryptographically random opaque `ClientId`, persists the key and fingerprint via Directory, then invokes the host hook. The hook receives `client_id` and public identity metadata only. A failure before Directory publication returns no client ID; a hook failure is surfaced as `ENROLLMENT_HOOK_FAILED` and is not silently treated as complete. Host account mapping remains host-owned.

Custody initializes two shares for the required 2-of-2 arrangement, stores only sealed shares/commitments and key-check values with an epoch, and reconstructs the per-client server key only in scoped secret memory for the operation that needs it. It is never persisted or returned by a port. Records use a fresh per-record DEK, authenticated envelope encryption and wrapped DEK under the server key; nonce, tag, AAD, key ID/epoch, ciphertext, and wrapped DEK are stored as required by the normative format. Delete removes the matching record. Exact algorithms, AAD composition, key-check derivation, and wiping rules are normative, not implementation-selected.

Recovery persists a pending recovery ID, owner, epoch, threshold, expiry, and state. A trustee release is bound to that pending ID and that trustee; duplicate approvals are idempotent, conflicting decisions are rejected. Completion requires at least configured `k` valid shares for the same active pending recovery and epoch; cancelled/expired/completed recoveries reject release and completion. Reconstruction, commitment verification, resealing, cancellation, rotation, and notification payloads follow the normative protocol. No share is logged or returned outside the recovery operation.

**Recovery start, notification and authorization (F-5, T-18; spec §8.3).** Each recovery operation is authorized as follows:

| Operation | Principal | Authorized by | `recovery_id` role |
|---|---|---|---|
| `recover_start` | None. The new device has no `cs`. | The optional host admission hook over `trigger_evidence` (D-011), then the admission bounds. `owner_id` is the **subject**: it selects whose recovery is started and is never an authenticated principal. | Minted here with 16 random bytes |
| `release_share` | Authenticated trustee session | The principal is a nominated trustee of the owner's current epoch, and the recovery is in state `PENDING` and not expired | Selects the recovery; grants nothing |
| `recover_complete` | None | The supplied `RIB_priv` derives the `RIB_pub` recorded for that recovery (constant-time compare), plus ≥ `k` verified re-sealed shares (spec §8.3 step 3) | Selects the recovery; grants nothing |
| `recover_cancel` (spec §8.3 step 4; D-008) | Authenticated owner session | Principal `client_id` == the recovery's `owner_id` and state `PENDING` | Selects the recovery; grants nothing |

`recover_start` runs in this order, and every step fails closed:
1. Protocol checks (spec §5.4 steps 12–14).
2. Directory resolves `owner_id` to an enrolled client with an active epoch and a trustee set for it. Otherwise `UNKNOWN_CLIENT`, recorded as a pre-principal aggregate.
3. Global recovery budget (ADR 0004). This also bounds how often the admission hook runs.
3a. Host admission hook, if registered (see below). Rejection or hook failure ends processing here with no state change, and the request does **not** count toward the per-owner bounds.
4. `create_pending_recovery` with `MAX_PENDING_RECOVERIES_PER_OWNER` and `RECOVERY_STARTS_PER_OWNER` per `RECOVERY_START_WINDOW`. Exceeding them returns `LIMIT_EXCEEDED` with no state change. Project defaults, overridable and not normative, are 2 pending and 4 starts per 24 h. They are `BoundaryLimits` values and must be finite and ≥ 1.
5. Audit intent/outcome records (see "Protected audit").
6. `Notifier.notify(owner_id, RECOVERY_PENDING)`. Recipient `owner_id` is the owner's client ID, and the host delivers it to the owner's existing device(s) through its own channel.
7. `Notifier.notify(trustee_id, RECOVERY_REVIEW_REQUESTED)` for each nominated trustee.

The start succeeds only after step 7 is accepted. If any notification fails, the recovery goes to `CANCELLED` and the request returns `BACKEND_UNAVAILABLE`, so no pending recovery exists that the owner was not told about. The owner is notified before trustees so that a trustee never acts on a recovery the owner has not been told about.

**Host recovery-admission hook (D-011, T-21; INC-4).** This is an optional host policy over `trigger_evidence` (spec §8.3 step 1). Spec §2 makes the trigger policy host-owned, so the library supplies only the hook point. It is registered alongside `on_enroll`:

```python
@dataclass(frozen=True)
class RecoveryAdmissionRequest:
    owner_id: ClientId           # Directory-resolved subject (step 2); never a principal
    trigger_evidence: bytes      # as decoded from the recover_start payload per spec/wire; opaque to the library
    received_at: datetime        # workload clock, UTC

class AdmissionDecision(Enum):
    ADMIT = "ADMIT"
    REJECT = "REJECT"

RecoveryAdmissionHook = Callable[[RecoveryAdmissionRequest], AdmissionDecision]

@app.recovery_admission          # Workload.recovery_admission(hook) -> hook
def admit(req: RecoveryAdmissionRequest) -> AdmissionDecision: ...
```

**Registration.** At most one hook may be registered. A second registration, or a non-callable, fails configuration with `INVALID_OPERATION_REGISTRATION`.

**Input.** The hook receives no key, share, `RIB_pub`, session material or `recovery_id`; the `recovery_id` is not yet minted at this point. Before the hook runs, `trigger_evidence` is validated as a byte string no longer than `MAX_TRIGGER_EVIDENCE_BYTES` (`BoundaryLimits`). A value that exceeds the limit returns `INVALID_FRAME` and is counted in the aggregate `RECOVERY_START_INVALID`. If `spec/wire` types `trigger_evidence` as anything other than a byte string, raise a CONTRACT_ISSUE. Do not adapt the hook silently.

**Execution.** The hook runs inside the TEE as host code. It is synchronous and must decide within `RECOVERY_ADMISSION_DEADLINE` (`BoundaryLimits`). The workload's egress is limited to attestation, KMS, storage and queue (spec §11 line 290), so the hook cannot call host services over the network. Evidence must be self-verifiable, for example a host-signed recovery assertion checked against a public key in the attested, release-versioned configuration. The README states this.

**Outcomes.** All three outcomes below leave no state mutation, no notification and no count toward `MAX_PENDING_RECOVERIES_PER_OWNER` or `RECOVERY_STARTS_PER_OWNER`:

| Hook result | Peer-facing result | Audit (`AGGREGATE`, with `count`) |
|---|---|---|
| `REJECT` | `NOT_AUTHORIZED` | `RECOVERY_ADMISSION_REJECTED` |
| Exception, deadline exceeded, or a return value that is not an `AdmissionDecision` (fail closed) | `BACKEND_UNAVAILABLE` | `RECOVERY_ADMISSION_FAILED` |
| `ADMIT` | Continues to step 4 | — |

Exception text is never logged or returned.

**Default with no hook.** Every request that passes steps 1–3 is admitted. This is the pre-D-011 behaviour, and T-21 then remains as accepted in D-010. The README recommends registering a hook.

**Interaction with `LIMIT_EXCEEDED`.** Only admitted requests reach `create_pending_recovery`, so only admitted requests can be counted or receive `LIMIT_EXCEEDED`. An attacker without acceptable evidence cannot consume an owner's pending slots or start budget. An admitted request over the bound still gets `LIMIT_EXCEEDED` with no state change. The per-owner bounds remain in force even when a hook is present, as defence in depth against a permissive hook.

**`recover_cancel` (D-008).** This is a built-in reserved operation, and it is valid only inside an open owner session.

The logical input is `recovery_id`. The canonical payload is defined in `spec/wire` CDDL when that is authored; that is a human-controlled change, and no encoding is invented here.

Processing order:
1. Load `PendingRecovery` by `recovery_id`.
2. Authorize: principal == `owner_id` and state == `PENDING`. An unknown ID or a failed check returns `NOT_AUTHORIZED` (same result for both).
3. Write the audit intent.
4. `transition_recovery(PENDING → CANCELLED)`.
5. Delete the re-sealed shares (spec §8.3 step 4).
6. Write the audit outcome `RECOVERY_CANCELLED`.

The operation is idempotent for an already-`CANCELLED` recovery owned by the principal. It returns success with no second transition.

Client: `@teecustody/core` exposes `client.cancelRecovery(recoveryId)` on an open owner session. Expiry after `RECOVERY_TTL` follows the same steps 3–6 from a timer, with outcome `RECOVERY_EXPIRED`.

## Data ownership and migration

| Data | Source of truth and owner | Persistence rule |
|---|---|---|
| Trust profile and signer policy | Host/release configuration | Version-controlled profile; simulator anchors excluded from production artifacts. |
| Client public identity/fingerprint and opaque `client_id` | Directory adapter | Public data only; host account mapping remains host-owned. |
| Custody shares, commitments, key-check values, active epoch/key IDs | ShareStore/TrusteeStore according to role | Shares sealed; never persist reconstructed per-client server keys. |
| Encrypted records and wrapped DEKs | RecordStore | Ciphertext and required envelope metadata only; plaintext and unwrapped DEK are transient. |
| Queue requests/responses | Queue adapter | Canonical authenticated envelopes; TTL/retention set by adapter configuration, with no plaintext application payload. |
| Recovery state | TrusteeStore | Pending-state transitions are conditional/atomic; terminal states cannot release shares. |
| Web client share vault | User browser, owned by user | IndexedDB stores ciphertext only; wrapping key is derived on demand from WebAuthn PRF. |
| Workload audit and alert records; release sign-off and signer verification records | Audit Project workload audit bucket | Create-if-absent objects under retention lock; allow-listed fields only; no reader, overwriter or deleter among workload-project principals. |
| Platform audit logs (Admin Activity, Data Access for KMS/STS/audit-bucket storage, client security-event log) | Audit Project `platform-audit` log bucket via aggregated sink | Locked retention; sink defined above the workload project; IAM principals present (these are platform logs, not workload logs). |
| Web bundle hash manifests | Release artifacts, signed per ADR 0006 | Published with each web release; reproduced by signers. |

Production adapter schema changes are additive where possible and versioned with explicit migration code. Never migrate or log plaintext secrets. Epoch transition is explicit: write and verify the new sealed epoch, atomically mark it active, then handle old epochs as the normative ShareStore contract specifies. Simulator stores implement equivalent observable semantics without claiming production durability.

## Security, errors, and operations

- Attestation and authenticated-channel checks fail closed before trust, operation dispatch, or custody access. Client verification remains independent of workload enforcement.
- Workload interfaces are queue pull only. The gateway is a separate example process and is not an inbound TEE endpoint.
- `Secret` repr is redacted. Secret-bearing buffers are explicitly wiped where specified, acknowledging Python runtime limitations. Logging is structured and allow-listed (`client_id`, `request_id`, `session_id`, `prekey_id`, `epoch`, timestamps, outcome codes only).
- Library errors are typed categories with sanitized messages. HTTP mapping is limited to the reference gateway contract above. Retry only idempotent operations; security rejection is not retried as a success path.
- Host configuration comprises the approved `AUDIENCE`, `TOKEN_TYPE`, digest allow-list, signer keys, `SIGNERS_REQUIRED`, and trustee `k`/`n`; remaining defaults come from the normative specification. No runtime secrets are provisioned. Credentials come from attested platform identity, and key material is reached only through Cloud KMS (see "Secret and configuration lifecycle"). Configuration is non-secret, versioned with the signed release, and never contains secrets.
- No i18n/RTL or user-facing UI requirement is stated except the example workflow; the web package exposes errors to its host and does not prescribe a UI.

## Security boundary contracts

### Validation and resource bounds (SR-3, SR-4)

Each component that accepts data from a less-trusted component owns validation at that boundary. Validation occurs on raw byte length before decoding, then on strict typed/schema shape, field ranges, cross-field invariants, and configured depth/count limits before domain logic, state mutation, cryptographic work, or backend access. Wire values must be canonical CBOR conforming to the normative CDDL; truncated, noncanonical, malformed, or out-of-schema values fail closed. No permissive decoder fallback is allowed. Unknown fields are rejected unless the controlling normative schema explicitly permits them.

This rule applies to gateway routes and cursors; queue messages and cloud adapter responses; attestation, bundle, and session parsers; simulator HTTP/socket/CLI inputs and generated configuration; workload configuration; host hook inputs and handler outputs; TypeScript Fetcher responses; and WebAuthn, IndexedDB, and WebCrypto capability results. Adapters validate provider responses before returning typed port values. Stable public errors contain only the documented category and never provider content.

`BoundaryLimits` is required configuration for byte size, nesting depth, collection/count size, polling wait, concurrency, and relevant operation deadlines. Every configured limit must be finite, positive, and validated at startup; missing, non-finite, or inconsistent values prevent production startup. Normative maxima take precedence; this architecture does not invent protocol sizes or weaken normative limits. Deployments must select and record operational values before release.

The Reference Gateway remains unauthenticated and untrusted under D-003. It checks bounded request size and route syntax, and applies per-source plus global rate/concurrency limits before queue work. Route IDs are opaque routing hints only: possession never authenticates a caller, selects an authoritative principal, or grants access. Queue adapters cap pull batches and wait times; workload retries have finite attempts and bounded delay; expensive verification and recovery operations have per-authenticated-principal and global concurrency/work budgets. Pre-authentication limits use source and global budgets, never route IDs as identity. Over-budget work is rejected with a stable error before state mutation; custody transitions are never silently dropped. Simulator ingress uses equivalent finite limits.

### Authorization and tenant scoping (SR-1, SR-2, SR-8)

The workload dispatch boundary obtains the principal only from successfully authenticated protocol state and its Directory binding. Before handler invocation or backend access, the library authorization policy checks the principal, library-owned operation, resource owner, active epoch, and pending recovery state as applicable. A denial causes no handler invocation, secret access, or backend mutation. Route IDs, request metadata, and client-asserted identities are never authorization inputs.

Library authorization covers built-in custody/recovery operations and library-owned resources. For host-registered operations, the library performs protocol, registration, and tenant-boundary checks; authorization of host accounts, host records, and other application policy remains the host application's responsibility. Successful library authentication does not imply host authorization. Host handlers must enforce their host-owned policy before acting on host data.

Backend calls receive tenant and owner identifiers derived from the authorized context, not copied from untrusted payloads. Every tenant-scoped adapter validates identifiers and constructs storage keys within that scope; mismatch, absent scope, epoch mismatch, or recovery mismatch fails closed. Workload and adapter platform identities have only the minimum queue, KMS, and store permissions needed for their assigned ports. The gateway can perform only its assigned queue relay operations and has no KMS/store permissions or authority to make these decisions. The simulator uses local development credentials only and cannot assume production identities. CI has no runtime-store or release-signing credentials; release signers have no runtime data-plane permissions.

### Production transport (SR-5)

Every networked production adapter, including queue, KMS, Firestore/GCS, Directory, TrusteeStore, Notifier, configuration access, and the production-facing reference transport, uses authenticated encrypted transport. Adapters validate the expected platform service identity and configured trust roots, reject plaintext endpoints and downgrade, and do not follow redirects to an untrusted origin. Platform SDKs must retain certificate and service-identity validation; custom insecure transport overrides are prohibited. Simulator loopback endpoints are development-only and cannot be selected by production profiles.

### Protected audit (SR-6; T-05; ADR 0005 and its amendment)

There are two audit paths. Neither path depends on anything that workload-project administrators control.

**1. Workload audit records (in-TEE events).** The Workload Audit and Alert Emitter writes through the `AuditSink` port. In production it uses `GcsAuditSink` against the **workload audit bucket, which lives in the Audit Project**, a GCP project separate from the workload project. Cross-project IAM follows SR-8 exactly. Any principal that holds a role on the workload or gateway project holds at most two things in the Audit Project:
- (i) the attested workload identity's `storage.objects.create`, conditioned to the `event/`, `alert/` and `aggregate/` prefixes of the workload audit bucket;
- (ii) the read-only audit-reader role.

Such a principal holds no admin, IAM-set, bucket-update, retention, delete, or sink/log-bucket permission there. The SR-8 automated policy check enforces this rule as written. The bucket has uniform bucket-level access, no public access, and Bucket Lock with an explicitly approved retention duration, set and locked before production use. The attested workload identity has only `storage.objects.create`, restricted by IAM condition to the `event/`, `alert/` and `aggregate/` prefixes. It cannot read, list, overwrite or delete. Named release owners and signers have create-only on `release/` and hold no workload-project admin role. Audit readers and retention administrators are separate Audit Project principals. Writing to this bucket stays inside the workload's permitted egress to storage (spec §11 line 290).

Writes are **create-if-absent**: object names are deterministic and the GCS precondition is `ifGenerationMatch=0`. The emitter never overwrites. An `ALREADY_EXISTS` result is handled like this:
- The emitter treats the record as present, so idempotency holds.
- It also appends an `AUDIT_WRITE_CONFLICT` record under class `ALERT`, with a fresh random ID and the conflicting `request_id`, which raises an alert (see "Security alerting").

A legitimate retry after an ambiguous network failure can therefore raise an alert. The design accepts these rare, investigable false positives rather than giving the writer read access.

Record classes and when each is written:

| Event | Class | Granularity | Object ID |
|---|---|---|---|
| Authorization denial of an authenticated principal (SR-2) | `EVENT` | Per event | `<request_id>/denied` |
| State-changing security operation: recovery start, trustee approval/rejection, terminal recovery transition (complete, cancel, expire), `rotate_share`, `rotate_sk`, `set_trustees` | `EVENT` | Intent before mutation, outcome after | `<operation_id>/intent`, `<operation_id>/outcome` |
| `kcv` mismatch, rejected trustee share, audit write conflict, pre-key burn above threshold | `ALERT` | Per event for authenticated principals; first-per-interval and capped for pre-principal (below) | `<operation_id>/<outcome>` or a random ID |
| Failures before a principal exists: HPKE `Open` failure, unknown/consumed `prekey_id`, stale timestamp, replayed `request_id`, session-frame authentication failure, unknown `client_id` on `recover_start` | `AGGREGATE` | One record per outcome code per instance per `AUDIT_AGGREGATE_INTERVAL`, written at interval end only if `count` ≥ 1; carries `count` (D-012) | `<interval_start>/<outcome>/<random>` |
| Release and trust-configuration sign-offs, signer verification records (spec §12 line 302; ADR 0006) | `RELEASE` | Per owner/signer per change | `<change_id>/<signer_or_owner_id>` |

`operation_id` is the request's `request_id` for request-driven operations. For timer-driven transitions such as recovery expiry, it is 16 random bytes generated by the workload. Pre-principal aggregates bound storage: at most (number of pre-principal outcome codes) objects per instance per interval, however many anonymous requests arrive (F-1(e)). An anonymous sender can trigger pre-principal alert-class events, because `open_session` and `recover_complete` reach the `kcv` check without an established principal (spec §5.4, §7.2). For those events:
- The first occurrence per `(outcome, subject_client_id)` per interval is written immediately as an `ALERT`, so alert latency is not delayed.
- Later occurrences in the same interval fold into that interval's `AGGREGATE` record.
- At most `AUDIT_ALERT_CAP` alert objects are written per instance per interval. Beyond the cap, one `ALERT_CAP_REACHED` alert is written.

`AUDIT_AGGREGATE_INTERVAL` and `AUDIT_ALERT_CAP` are `BoundaryLimits` values: finite and validated at startup. Aggregates are held in memory and are lost if an instance crashes mid-interval. That loss is accepted for aggregates only; per-event records follow the fail-closed rules below.

Failure semantics are unchanged from ADR 0005:
- **Authorization denial:** the service denies regardless of audit availability, and records the denial before returning its stable result. If recording fails, the result is a sanitized `BACKEND_UNAVAILABLE` and the operation is still not permitted.
- **State-changing operation:** a durable intent is written before mutation, then one outcome is written with the same `operation_id` once the result is known. The operation is not acknowledged as successful until the outcome is durable. Reconciliation reuses the same ID and never repeats the transition.
- **Retention:** there is no silent-expiry or early-delete path.

Audit data never contains payloads, tokens, credentials, cryptographic material, provider exceptions or host data.

**Audit record fields (F-1(a); decided by H-1, D-007).** Audit records use role-qualified identifiers. The plain `client_id` field is not used in audit records; it remains the general-log field. Field meanings and sources:

| Field | Meaning | Source (never copied from the request payload) |
|---|---|---|
| `actor_client_id` | The authenticated principal who performed the action | Session state after frame authentication and Directory resolution. Absent when no principal exists (`recover_start`, `recover_complete`, timer-driven expiry, pre-principal events). |
| `subject_client_id` | The client whose resource the action targeted | The stored record the policy authorized against: the `PendingRecovery.owner_id`, share/epoch owner or record owner. For `recover_start`, the Directory-resolved owner of the admitted request. For pre-principal `kcv` events, the `client_id` in the HPKE-authenticated AAD. |
| `recovery_id` | The recovery the action concerned | `PendingRecovery.recovery_id` of the stored record that was loaded, never the value as received |

Per-event field set. Every record also carries `outcome` and `ts`. `✓` = always present; `–` = absent. `epoch` means the owner's epoch acted on; for rotations and completion it is the new epoch.

| Event | Class | `outcome` | `actor_client_id` | `subject_client_id` | `recovery_id` | Other |
|---|---|---|---|---|---|---|
| Authorization denial of an authenticated principal | `EVENT` | `AUTHZ_DENIED` | ✓ | ✓ if the target resource was resolved, else – | ✓ if the target is an existing recovery, else – | `request_id`, `session_id`, `epoch` if resolved |
| `set_trustees` | `EVENT` intent/outcome | `TRUSTEES_SET` / `…_FAILED` | ✓ (owner) | ✓ (owner) | – | `request_id`, `session_id`, `epoch` |
| `release_share`: trustee approves | `EVENT` intent/outcome | `TRUSTEE_RELEASED` | ✓ (trustee) | ✓ (owner) | ✓ | `request_id`, `session_id`, `epoch` |
| Trustee declines | `EVENT` | `TRUSTEE_DECLINED` | ✓ (trustee) | ✓ (owner) | ✓ | `request_id`, `session_id`, `epoch` |
| Trustee share fails verification | `ALERT` | `TRUSTEE_SHARE_REJECTED` | ✓ (trustee) | ✓ (owner) | ✓ | `request_id`, `session_id`, `epoch` |
| `recover_start` admitted | `EVENT` intent/outcome | `RECOVERY_STARTED` / `RECOVERY_START_CANCELLED_NOTIFY_FAILED` | – | ✓ (owner) | ✓ | `request_id`, `epoch` |
| `recover_start` over the per-owner bound | `AGGREGATE` | `RECOVERY_START_LIMITED` | – | – | – | interval timestamps, `count` |
| `recover_start` rejected by the host admission hook | `AGGREGATE` | `RECOVERY_ADMISSION_REJECTED` / `RECOVERY_ADMISSION_FAILED` | – | – | – | interval timestamps, `count` |
| `recover_complete` succeeds (includes the forced rotation) | `EVENT` intent/outcome | `RECOVERY_COMPLETED` | – | ✓ (owner) | ✓ | `request_id`, `epoch` (new) |
| `recover_complete` rejected (wrong `RIB_priv`, < k shares, terminal state) | `AGGREGATE` | `RECOVERY_COMPLETE_REJECTED` | – | – | – | interval timestamps, `count` |
| `kcv` mismatch (open_session or recover_complete) | `ALERT`, first-per-interval and capped | `KCV_MISMATCH` | – | ✓ (from AAD) | ✓ if in recover_complete, else – | `request_id`, `epoch` |
| `recover_cancel` | `EVENT` intent/outcome | `RECOVERY_CANCELLED` | ✓ (owner) | ✓ (owner) | ✓ | `request_id`, `session_id`, `epoch` |
| Recovery expiry (timer) | `EVENT` intent/outcome | `RECOVERY_EXPIRED` | – | ✓ (owner) | ✓ | `epoch`; `operation_id` is random |
| `rotate_share` / `rotate_sk` | `EVENT` intent/outcome | `SHARE_ROTATED` / `SK_ROTATED` | ✓ (owner) | ✓ (owner) | – | `request_id`, `session_id`, `epoch` (new) |
| Audit write conflict | `ALERT` | `AUDIT_WRITE_CONFLICT` | – | – | – | `request_id` of the conflicting write |
| Pre-principal failures (table above) | `AGGREGATE` | per code | – | – | – | interval timestamps, `count` |
| Alert cap reached, pre-key burn | `ALERT` | per code | – | – | – | interval timestamps |

Pre-principal alert dedup is keyed on `(outcome, subject_client_id)`. `recovery_id` and the role-qualified fields are permitted in **audit records only** (D-007). General logs, including `LogNotifier`, keep the base allow-list.

**Structural rule: `recovery_id` is never an authorization input or bearer token.**
- The workload authorization policy function takes `(principal, operation, resource)`, where `resource` is the loaded `PendingRecovery` record. It has no `recovery_id` parameter.
- The dispatcher uses the received `recovery_id` only as a lookup key.
- Every grant is decided on the principal and the stored record's `owner_id`, nominated trustee set, `state`, `expires_at` and `rib_pub`.
- An unknown `recovery_id` and an unauthorized one return the same `NOT_AUTHORIZED`, so a caller cannot probe which IDs exist.
- Enforcement is by review checklist plus a static rule (semgrep) that fails CI if the policy module's decision functions accept a parameter named or typed `RecoveryId`.
- The SR-2 test covers a non-nominated client that holds a valid `recovery_id`.

**`count` on aggregates (H-2 decided, D-012).** Every `AGGREGATE` record carries `count`: a non-negative integer equal to the number of occurrences of that outcome on that instance in `[interval_start, interval_end)`. Only records with `count` ≥ 1 are written. The counter saturates at 2^53 − 1, the largest integer JSON represents exactly. `count` is permitted only on `AGGREGATE` records. The `AGGREGATE` class is used only for failures and rejections before a principal exists. `EVENT`, `ALERT` and `RELEASE` records never carry `count`, and `AuditSink` rejects them with `INVALID_ARGUMENT` if they do.

**2. Platform audit logs (operator actions; spec §7.3 line 201, §12 line 302, §13.6).** Operators never authenticate to the workload. They are attributed by IAM principal in Cloud Audit Logs:
- **Audit log configuration** is set at the folder (or organization) level that contains the workload, gateway and Audit projects. Audit configs are additive down the resource hierarchy, so a project owner cannot turn them off. The configuration enables:
  - Admin Activity logs (always on);
  - Data Access logs (`ADMIN_READ`, `DATA_READ`, `DATA_WRITE`) for `cloudkms.googleapis.com` and `sts.googleapis.com`;
  - on the Audit Project, `DATA_WRITE` for `storage.googleapis.com`, so every audit-object creation is itself logged.
- **Aggregated sink** at that folder/organization level (`includeChildren`). Its destination is the `platform-audit` Cloud Logging bucket in the Audit Project, with retention set and locked. Its filter covers `cloudaudit.googleapis.com/activity`, `cloudaudit.googleapis.com/data_access` and `cloudaudit.googleapis.com/policy` from the included projects, plus the `teecustody-client-security` log (see "Security alerting"). Workload-project administrators cannot modify, delete or re-route a folder-level sink, and project-level exclusions do not affect it. The principals above the folder are the documented T-05 residual.
- **What this attributes:** KMS key IAM and key-version changes; WIP pool/provider and attribute-condition changes; custody-key decrypt attempts, including denials; changes to the sink, the audit buckets, their IAM or their retention.
- **Service-name caveat:** the exact service names, method names and filter syntax are verified against current Google Cloud documentation at INC-3 (spec §0 line 13; PROJECT.md R3) and recorded in the task report.
- The workload never calls Cloud Logging. These logs are emitted by the platform, so no workload egress is added.

**Security-relevant configuration and release events (F-1(c), spec §12 line 302).** Every change to the digest allow-list, signer set, WIP condition or KMS IAM follows this sequence:
1. Two named owners each write a signed sign-off record to `release/<change_id>/<owner_id>` using their own Audit Project identity. The record contains the change type, source commit and SHA-256 of the new allow-list / signer set / condition text. Owner identities hold no workload-project admin role.
2. The applying operator uses the audit-reader role to confirm that both records exist, then applies the change.
3. The platform logs the resulting Admin Activity entry to the protected sink with the operator's principal.
4. A change-notification alert (see "Security alerting") goes to the named owners. An applied change with no matching sign-off pair is an incident.

The client release that ships the updated trust profile, and its release notes, are the announcement to clients.

### Security alerting (SR-12; T-20, T-17; ADR 0007)

Spec §12 line 303 requires an alert for four events. Every alert path ends in a **log-based alert policy in the Audit Project** that evaluates the protected `platform-audit` log bucket. Notification channels (pager, email) are host-configured. None of the paths adds a network path into the TEE, and none adds workload egress beyond storage (spec §1 topology, §11 line 290).

| Event (spec §12) | Detected by | Path to alert | Carried fields |
|---|---|---|---|
| KMS decrypt denied by the WIP condition | Platform | (a) a Cloud KMS `Decrypt` Data Access entry with status `PERMISSION_DENIED` on the custody key; (b) an STS token-exchange denial for the Confidential Space WIP provider. A WIP attribute-condition failure can surface at STS, before any KMS call, so both are alerted. Both reach the sink, and one policy (`KMS_DECRYPT_DENIED`) matches either. | Platform log fields only (principal, resource, status) |
| `kcv` mismatch | Workload (spec §7.2 line 189) | Session aborts (fail closed). The emitter writes an `ALERT` object with outcome `KCV_MISMATCH` via `AuditSink`. Its creation is logged by the Audit Project's storage `DATA_WRITE` audit log, and the policy `WORKLOAD_ALERT` matches object names under `alert/`. | Outcome, `ts`, `subject_client_id`, `recovery_id` (if in `recover_complete`), `epoch`, `request_id` |
| Rejected trustee share | Workload (spec §8.3 step 2) | Share rejected by index. `Notifier` sends `SHARE_REJECTED` to the owner (FR-13). The emitter writes `ALERT` `TRUSTEE_SHARE_REJECTED`, which fires the same `WORKLOAD_ALERT` policy. | Outcome, `ts`, `actor_client_id` (trustee), `subject_client_id` (owner), `recovery_id`, `epoch`, `request_id` |
| Debug-mode token seen by a client | TypeScript Core (spec §6.6) | 1. Core calls the injected `SecurityEventSink` (see the verifier contract), after signature and issuer have passed. 2. `BeaconSecurityEventSink` POSTs `{"code":"ATTESTATION_DEBUG_MODE"}` to the host's same-origin endpoint. 3. The notes-app host serves `POST /security-events`. It is unauthenticated per D-003, accepts only the closed code enum in a body of at most 64 bytes, applies per-source and global limits (SR-4), and returns `204`. It emits one structured entry `{event:"client_security_event", outcome, timestamp}` to log `teecustody-client-security`. 4. The aggregated sink routes that log to the Audit Project, where policy `CLIENT_DEBUG_MODE_TOKEN` fires. | Code and timestamp only; no token, claims or instance ID |

Additional alert policies on the same sink:
- `WORKLOAD_ALERT` also covers `AUDIT_WRITE_CONFLICT` and `ALERT_CAP_REACHED`.
- `PREKEY_BURN_HIGH` (SR-12 SHOULD, T-17): the workload writes this `ALERT` when pre-keys consumed per interval exceed `PREKEY_BURN_ALERT_THRESHOLD`, a `BoundaryLimits` value. As an `ALERT` it carries no `count` (D-012 limits `count` to aggregates).
- `TRUST_CONFIG_CHANGED`: any Admin Activity change to the custody key's IAM, the WIP provider/condition, the sink, or the audit buckets' IAM/retention. It notifies the named owners so they can match the change to a sign-off pair (see "Protected audit").

Rules:
- An alert never carries a token, key, share, nonce, ciphertext or payload.
- The triggering operation fails closed whether or not alert emission succeeds.
- Alert emission failure is handled as an audit write failure (ADR 0005).

The client-reported path is detection only. An attacker who controls the web origin or gateway can suppress reports, and anyone can send spoofed reports, bounded by rate limits. The client rejects the token regardless. Hosts that do not use the notes-app server must provide an equivalent endpoint and route its log to their protected sink. The host README states this as a required integration step.

**Simulator equivalents.**
- `InMemoryAuditSink` exposes `alert/` records to tests.
- The notes-app route logs to stdout, and tests capture it.
- Core tests use an in-memory `SecurityEventSink`.
- The KMS/STS path is tested only against real GCP (spec §13.6, §15.2 item 4).

### Secret and configuration lifecycle (SR-7)

Production workload credentials come from Confidential Space platform identity, not static credentials in images, environment files, or source. Secret key material already assigned to Cloud KMS is accessed only through the existing Cloud KMS adapter and least-privilege workload identity; key bytes are not exported to application configuration. Other non-secret configuration, including production trust profiles, is validated at startup and versioned with the signed release; production startup rejects simulator anchors and unknown or malformed security settings. Trust-profile, digest allow-list, or signer-set changes follow the existing human escalation and release approval rules. Simulator signing keys remain local development material and are rejected by production trust profiles.

Rotation uses versioned keys/configuration in the already-approved Cloud KMS and release configuration: provision and validate the replacement, switch authorized consumers, verify operation, then revoke the superseded version. Revocation prevents subsequent use; no cached secret may outlive the approved operation scope. Access and rotation are performed by separately authorized operators. They are attributed by IAM principal in the platform audit sink (see "Protected audit") and never expose secret bytes in responses or logs. No Secret Manager, new identity system, or additional cloud service is introduced.

### Release signer governance (SR-10; T-13; ADR 0006 and its amendment)

CI and cloud workloads build reproducible, unsigned artifacts from pinned source and dependency inputs. They hold no release-signing keys, signing permission, or package-registry publish credentials, and they cannot satisfy release approval. CI output (digest, provenance) is **input to the signers, never the basis for signing** (spec §12 lines 299–301: "build, reproduce, sign").

**Signer procedure** (`release/` tooling). Each of at least `SIGNERS_REQUIRED` distinct human signers performs every step, independently of each other and outside both the cloud project and the CI system:
1. **Check out.** Fetch the approved source commit, identified by full commit hash from the human release approval, into a clean checkout on the signer's own workstation. Use no CI caches, CI artifacts or CI-produced images.
2. **Rebuild.** Run the published build recipe. All inputs are pinned by hash in the approved commit: the base image and builder image by digest, and lockfiles with hashes. The recipe sets `SOURCE_DATE_EPOCH` from the commit and has no unpinned network fetch.
3. **Compare.** Compute the reproduced digest and compare it with the candidate digest, i.e. the CI-reported digest of the artifact proposed for release.
4. **Refuse on mismatch.** On any difference, stop and do not sign. The mismatch is a release blocker and is reported as a security event.
5. **Sign on match.** Sign the digest with the signer's image-signing key, using the signature format the Confidential Space image-signature claims require (spec §6.8, §12; format verified against current documentation at INC-5 per spec §0). Any F-11 algorithm is acceptable: `RSASSA_PSS_SHA256`, `RSASSA_PKCS1V15_SHA256` or `ECDSA_P256_SHA256`. The trust profile records each signer's `key_id` (SHA-256 of its SPKI DER) together with that algorithm (D-016).
6. **Record.** Write a **verification record** signed with a separate record-signing key held on the same device. It contains: `artifact_kind`, `artifact_name`, `source_commit`, `recipe_version`, `builder_image_digest`, `reproduced_digest`, `candidate_digest`, `match: true`, `signer_id`, `signed_at`, and the signer's build-host OS. Publish it with the release artifacts, and write it to the protected audit bucket as class `RELEASE`.

Signing keys are generated on, and non-exportable from, a hardware token held by the signer (the Security Architect's SHOULD, adopted as the default). Any exception is recorded in the release record. Image-signing keys sign only artifact digests. No two signers use the same build host.

**Deploy/publish verification.** Deployment (adding a digest to the WIP condition and the client trust profile) and package publication both require the following:
- ≥ `SIGNERS_REQUIRED` valid signatures from distinct approved signer identities over the artifact's digest;
- the same number of verification records whose `reproduced_digest` equals that digest.

The step rejects missing, invalid, tampered, wrong-key, single-identity-duplicate and digest-mismatched cases. The WIP condition and the Google attestation service verify the image signatures again. The clients independently require at least `SIGNERS_REQUIRED` embedded signer `key_id`s in the Google-signed token (spec §6.8 per D-016).

**Artifact scope ("where applicable").**

| Artifact | Reproduce and sign | Publication |
|---|---|---|
| Workload image | Always | CI may push the unsigned image to the registry. It is unusable until its digest is allow-listed after signing. |
| `teecustody` / `teecustody-sim` wheels and sdists; `@teecustody/core` / `@teecustody/web` tarballs | Always, byte-reproducible | A release owner publishes the reproduced, signed files from outside CI. |
| Notes-app web bundle | Signers reproduce the bundle hash manifest (ADR 0008) and sign the manifest digest | Published with the example release |
| Host web bundles | Host-owned | The README requires a reproducible build and a published manifest, and recommends this same procedure. |

The signer set and trust profile are not changed by this policy. Any change remains subject to human approval and the sign-off flow in "Protected audit". No signing service, cloud service, or runtime dependency is added. The residual risk is compromise or collusion of `SIGNERS_REQUIRED` signers.

### Web code delivery (SR-13; T-19; spec §10.3; ADR 0008)

The web client's §6 checks run in JavaScript served by the web-app origin, which is partially trusted for code delivery (spec §1, §10.3). Each §10.3 control is enforced as follows:

| Control (spec §10.3) | Enforced where | How it is tested |
|---|---|---|
| Library code runs under strict CSP: no `eval`, no `new Function`, no inline script, no string-to-code timers, no dynamic `import()` of computed specifiers | `@teecustody/core` and `@teecustody/web`: ESLint `no-eval`, `no-implied-eval`, `no-new-func` and a `no-restricted-syntax` ban on `import()` with non-literal arguments; a post-build bundle scan over each package's shipped output **including bundled dependencies** | CI on every change from INC-2: the bundle scan fails on `eval(`, `new Function`, `Function(` or a computed `import(`. A headless-browser harness page runs the vault and transport under the strict CSP in enforce mode and asserts zero `securitypolicyviolation` events. |
| Reproducible build with a published hash of every shipped bundle | `teecustody-profile manifest --dist <dir> --out bundle-manifest.json`. It emits sorted-key JSON `{source_commit, profile_kind, files:[{path, sha384}]}` for every shipped file. The build uses a pinned toolchain, `SOURCE_DATE_EPOCH`, content-hashed file names and no code splitting (dynamic chunks cannot carry SRI). | Two clean CI builds in separate containers produce identical manifests. Before release, signers reproduce and sign the manifest (ADR 0006). |
| SRI on every script | `teecustody-profile check-html --dist <dir> --manifest bundle-manifest.json --key-pages <glob>`. It fails unless every `<script>` has a `src`, an `integrity="sha384-…"` equal to the manifest hash, and `crossorigin` where needed. Also fails on inline `<script>` bodies, inline event-handler attributes and `javascript:` URLs. | CI static check on the notes-app build; unit tests of the checker with violating fixtures |
| Strict CSP, with `script-src` restricted to hashed or SRI-tagged resources | `teecustody-profile csp --manifest … --profile trust-profile.json --connect <origin>…` emits the header value: `default-src 'none'; script-src <'sha384-…' per manifest script>; connect-src <gateway origin> <new URL(profile.jwks_uri).origin> <security-event origin>; img-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'`. There is no `'self'`, `'unsafe-inline'`, `'unsafe-eval'` or `'strict-dynamic'` in `script-src`. The notes-app static host sends it as an HTTP response header, not a meta tag. | Headless-browser test of the notes-app enroll → put → close → open → get flow with the header in enforce mode, asserting zero violation reports. A unit test asserts the emitted header grammar. |
| No third-party scripts on key-handling pages | `check-html` fails on any script origin other than the page origin on pages matching `--key-pages`. The default is every HTML file. In the notes-app, every page handles keys and all JavaScript is self-hosted. | Same CI static check |
| State the residual limit | Host Integration README ("Web code delivery" section): the four controls above are **required** for hosts, and the README states that the origin remains trusted for code delivery; published hashes enable detection, not prevention; mobile is the long-term answer. | README review item in the INC-5 release checklist; the traceability row for §13.8 references T-19. |

Hosts must run `manifest`, `check-html` and `csp` in their own build. They must serve the emitted header and must not relax it. The library cannot enforce a host server's headers, so this is a documented host contract. The notes-app demonstrates it. FR-15's anchor check (`teecustody-profile` production check) runs in the same build step, together with `teecustody-profile check-discovery`. Every production build must run `check-discovery`, and it has no skip flag (ADR 0012).

Verification items for INC-2 (spec §0 line 13), recorded in the task report:
- (Superseded by ADR 0010: no package uses `cbor-x`, so V-2.1 is retired. The bundle scan still covers every bundled dependency. A dependency that reaches `new Function` or `eval` is a CONTRACT_ISSUE and is never met with `'unsafe-eval'`.)
- Target browsers must honor CSP hash sources for external scripts that carry SRI. Browsers that do not refuse to run the client (fail closed) and are recorded in the support matrix alongside WebAuthn PRF (PROJECT.md R2). Do not add `'self'` as a fallback.

## Deployment and integrations

The workload image runs in Google Cloud Confidential Space and pulls from the configured queue; platform launcher and workload identity supply attestation and Cloud KMS access. Production adapters use the configured Firestore, GCS, Pub/Sub, and Cloud KMS services. The reference gateway uses FastAPI and Queue. Under simulator, Docker/Podman runs the local launcher and OIDC issuer, and in-memory/local adapters provide the same ports without cloud credentials. The simulator is an independent development package and is absent from published library dependency graphs.

The production deployment has three kinds of project under one folder:
- the workload project (Confidential Space VM, Pub/Sub, Firestore, custody KMS key, record/share GCS);
- the gateway/web host, in the workload project or its own project;
- the **Audit Project**, which holds the workload audit bucket, the `platform-audit` log bucket and the alert policies.

The folder-level audit configuration and aggregated sink are defined at that folder or above. The notes-app documents this setup and scripts it under `examples/notes-app/deploy/`. The scripting tool is an INC-3 task choice and adds no runtime dependency. Cloud Audit Logs, the Cloud Logging sink and log-based alerting in Cloud Monitoring are platform configuration mandated by spec §7.3 line 201, §12 lines 302–303 and §13.6 (D-006). No package calls them at runtime.

Every runtime dependency must use an OSI-approved license and have a release within the configured 18-month window. Cryptographic dependencies are restricted to `cryptography`, `pyhpke` or Tink, `cbor2`, an approved libsodium Ristretto255 binding when required, `@hpke/core`, and `cbor-x`; pins include exact version and hash. Native WebCrypto may be used where the normative contract permits. No dependency implementing forbidden pure-Python/pure-JS primitives is allowed. Adding/replacing a crypto dependency needs an ADR and Security Architect sign-off. No JOSE library is used: JWS framing is project-owned and pinned to RS256 over audited RSA primitives (ADR 0009). No TypeScript package uses `cbor-x` (ADR 0010). Final package/version selection and license/maintenance evidence must be recorded before dependency lock files are approved.

## Testing strategy

- Unit: each attestation predicate and negative branch; session framing/sequence/replay; custody invariants; recovery state transitions; logger allow-list; Secret redaction/wipe behavior; vault PRF unsupported/failure cases.
- Contract/integration: each port against simulator and production-compatible contract suites; canonical CBOR round trips; launcher socket and simulator JWKS/discovery (including CORS parity and the attacker JWKS path, ADR 0012); queue routing; WebAuthn adapter with capability fakes; cloud adapters against isolated test resources where appropriate.
- Cross-implementation: simulator-generated positive and single-check negative vectors consumed by Python and TypeScript; byte-for-byte canonical encoding comparison.
- Acceptance: executable scenarios from the current increment criteria, simulator-first and credential-free. From INC-3 onward include that increment's Confidential Space smoke run; additionally scheduled and pre-release real-environment smoke tests.
- Security: every attestation predicate has a negative test; security paths have 100% coverage and all new code at least 80% line coverage. Run configured dependency, secret, static, and image scanners. TDD tests must fail for the intended reason before implementation.
- Audit/alert (SR-6, SR-12):
  - `AuditSink` contract suite, run against both adapters: create-if-absent, `ALREADY_EXISTS` producing an `AUDIT_WRITE_CONFLICT` alert, and allow-list rejection.
  - Pre-principal flood producing bounded `AGGREGATE` and capped `ALERT` objects.
  - The simulator scenarios in SR-12: corrupted `kcv`, corrupted trustee share, and `teecustody-sim token --alter dbgstat=enabled` driving the Core sink.
  - Scheduled real-GCP §13.6 checks: a denied decrypt lands in the sink and fires `KMS_DECRYPT_DENIED`; a workload-project owner cannot delete audit objects or modify the sink.
- Recovery (SR-2/SR-4, F-5):
  - A `recover_start` for another owner emits `RECOVERY_PENDING` to the owner before any trustee notification.
  - The per-owner pending and start-rate bounds return `LIMIT_EXCEEDED` without state change.
  - A notification failure leaves the recovery `CANCELLED`.
  - A non-nominated client holding a valid `recovery_id` cannot release.
  - `recover_complete` with the wrong `RIB_priv` fails.
  - `recover_cancel` by a non-owner, or with an unknown ID, returns the same `NOT_AUTHORIZED`.
  - Admission hook (D-011):
    - `REJECT`, exception and timeout each leave no pending record and no notification, and do not consume the per-owner bound: after N rejections, an admitted start still succeeds.
    - With no hook, every request is admitted.
    - A second registration fails.
    - Oversized evidence is rejected before the hook runs.
    - The hook input contains no `recovery_id` or key material.
  - Each audit event type carries exactly the fields in the "Audit record fields" table.
- Web delivery (SR-13):
  - Bundle scan.
  - `check-html` and `csp` unit tests.
  - Headless-browser enforce-mode CSP run with zero violations.
  - Two-build manifest equality.
- Release (SR-10):
  - The signer procedure refuses to sign when the reproduced digest differs from the candidate.
  - Deploy/publish verification rejects fewer than `SIGNERS_REQUIRED` matching records or signatures, and duplicate identities.
- Fixtures use synthetic public identities, test signers, and non-production secrets only. Never put real tokens, keys, shares, ciphertext, request bodies, or user data in fixtures, logs, or pull-request text.

## Release checks

CI runs the configured test, lint, strict type, coverage, and security scans without cloud credentials. Scheduled and pre-release CI runs Confidential Space smoke tests. Production profile generation and bundle scanning fail on any simulator trust anchor or verification bypass. INC-5 additionally proves reproducible workload image, package and web-manifest digests. It exercises the independent signer procedure end to end, including refusal on mismatch, and verifies the release signatures and verification records. It also confirms that the spec §12 sign-off records exist in the protected sink, checks all eleven normative deliverables and no-GAP traceability, exercises the documented notes workflow, and requires approved security review before v1.0.0.

## Design boundary requiring normative binding

This artifact intentionally does not replace the security architecture or wire specification. Before implementation contracts freeze, task contracts must copy the exact claim names, digest/nonce construction, CDDL field schemas and `proto`, cryptographic suites, AAD/key-check formats, and recovery/rotation algorithms from the normative documents. For the wire format, the normative document is the human-approved `spec/wire` binding (ADR 0002 amendment). External Confidential Space facts are copied from the verified `docs/tasks/INC-N/FACTS.md` record. No change under `docs/security/` is required by this architecture. If an implementation reveals a conflict, stop and return it for the required human-controlled security decision; do not edit the normative documents under this task.