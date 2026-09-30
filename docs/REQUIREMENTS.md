# Requirements

## Product Goal
Provide reusable Python and TypeScript libraries that let host applications establish an independently attested, forward-secret channel to a Google Cloud Confidential Space workload and use split-key custody and recovery for per-user data, without host-written cryptography; provide a simulator so the complete library suite and host integration can be developed and tested without cloud credentials.

## Functional Requirements

### INC-1: Attestation foundation

**FR-1 [INC-1] Workload attestation lifecycle.** The Python workload shall obtain an attestation token through the launcher socket, using the hash of its public identity key as the nonce, and refresh the token according to configured parameters.
- Given the simulator launcher and a configured workload, when the workload starts and requests attestation, then it obtains a token bound to the configured audience and identity-key nonce without requiring an inbound connection to the workload.

**FR-2 [INC-1] Independent client verification.** The TypeScript attestation module shall validate the token against an explicit trust profile, including the required claims, signer, nonce, audience, digest, and validity conditions defined by the normative security architecture; each check shall be independently testable.
- Given a valid simulator token and matching trust profile, when the client verifies it, then verification succeeds.
- Given a token with any required check altered or missing, when the client verifies it, then verification fails closed and does not establish trust.

**FR-3 [INC-1] Simulator token and vector tooling.** The simulator shall provide its launcher socket and loopback OIDC issuer with discovery and JWKS, development signing controlled by `SIGNERS_REQUIRED`, negative-token generation, and cross-implementation vector generation through the documented CLI.
- Given a local workload image and simulator configuration, when the simulator is started without cloud credentials, then it can issue tokens and support the attestation flow.
- Given a requested negative claim alteration or omission, when the simulator emits a token, then the corresponding client verification test rejects it.
- Given the vector-generation command, when vectors are generated, then output is written to the requested directory and is consumable by both implementations.

### INC-2: Encrypted channel and browser client

**FR-4 [INC-2] Secure request channel.** The client and workload shall establish sessions using signed pre-key bundles, HPKE RFC 9180 Base mode, session-key export, authenticated session framing with sequence numbers, and replay detection.
- Given a valid, unexpired bundle with an unused pre-key, when the client opens a session and sends an authenticated request, then the workload accepts and decrypts the request and returns an authenticated response.
- Given a request with invalid authentication, an invalid sequence, or a replayed sequence, when the workload processes it, then it rejects the request without dispatching its operation.

**FR-5 [INC-2] Queue-based transport.** The protocol shall use queue publication and pull; the workload shall not accept inbound connections. The reference gateway and web transport shall relay bundles, requests, and responses using their documented contract.
- Given the reference gateway and in-memory queue, when a browser client posts a request and polls for its response, then the request and response are relayed to the correct workload instance and client.

**FR-6 [INC-2] Client share vault.** The web package shall store the client share encrypted under a key derived from WebAuthn PRF output, with ciphertext in IndexedDB, and shall fail closed when PRF is unavailable.
- Given a browser with WebAuthn PRF support and a user-presence-approved vault operation, when the client stores and later retrieves its share, then only the encrypted share is persisted and retrieval requires deriving the wrapping key from PRF output.
- Given a browser or authenticator without usable PRF support, when a vault operation is attempted, then it fails closed without storing or exposing the share in plaintext.

### INC-3: Enrollment, custody, and records

**FR-7 [INC-3] Client enrollment and identity mapping.** The library shall mint an opaque random `client_id` at enrollment, return it to the client, publish the client's identity public key and fingerprint through the Directory interface, and invoke the host enrollment hook. The library shall not treat a client-asserted identity as authoritative.
- Given a new client and configured Directory, when enrollment succeeds, then the client receives a library-minted `client_id` and the Directory records the client's public identity and fingerprint.
- Given a request carrying a client-asserted identity, when the workload authorizes or routes it, then it uses the cryptographically authenticated client identity and Directory mapping rather than trusting that assertion.

**FR-8 [INC-3] Workload operations and record access.** The Python workload shall expose host handlers through operation registration and a session context with `client_id`, `session_id`, envelope-encrypted record operations, and a filtered logger. Built-in custody and recovery operation names shall be reserved and cannot be overridden by host handlers.
- Given a registered host handler, when a valid request for its operation is dispatched, then it receives the session context and payload and can use record put/get/delete/list operations.
- Given a host handler registration using a reserved built-in name, when the workload is configured, then registration is rejected.
- Given a handler using the session context, when it inspects the context, then it cannot obtain SKs, DEKs, shares, or session keys.

**FR-9 [INC-3] Split-key custody and encrypted records.** The library shall create the server share under the specified 2-of-2 scheme, maintain key-check values and epochs, and encrypt records using envelope encryption with per-record DEKs wrapped under the server key. Per-client server keys shall never be stored.
- Given enrollment and the configured custody backends, when custody is initialized, then the required shares and key-check value are created without persisting a per-client server key.
- Given a record write and subsequent authorized read, when the record is stored and retrieved, then the store contains ciphertext and a wrapped DEK with required nonce, tag, and AAD metadata, and the authorized handler receives the original plaintext.
- Given a record deletion, when the operation completes, then the corresponding stored record is removed according to the RecordStore contract.

**FR-10 [INC-3] Production and simulator adapters.** Each backend port (Launcher, Queue, KeyWrapper, ShareStore, RecordStore, Directory, TrusteeStore, and Notifier) shall have an explicit contract and a provided implementation appropriate to production or simulation as specified in `PROJECT.md`.
- Given production configuration, when the workload is assembled, then production adapters use the specified Google Cloud services, including Cloud KMS through attested workload identity.
- Given simulator configuration without cloud credentials, when the workload is assembled, then local or in-memory adapters provide the corresponding behavior.

### INC-4: Trustee recovery and rotation

**FR-11 [INC-4] Trustee setup and share release.** Clients shall be able to configure trustees and threshold `k`; trustee shares shall be sealed with verifiable share commitments and released only through the defined recovery flow.
- Given an owner, trustee set, and valid threshold, when trustees are configured, then the trustee store contains sealed shares and commitments for the applicable owner and epoch.
- Given a trustee and a valid pending recovery, when the trustee approves share release, then only that trustee's sealed share is released to the recovery flow.
- Given an invalid or unauthorized release request, when a trustee operation is attempted, then no share is released.

**FR-12 [INC-4] Recovery lifecycle.** The client and workload shall support recovery start, completion after the required threshold of shares, cancellation or expiry, and re-sealing of shares for the recovered client.
- Given a client beginning recovery, when recovery starts, then a pending recovery is recorded and trustees are notified.
- Given fewer than `k` valid shares, when recovery completion is attempted, then recovery does not complete.
- Given at least `k` valid shares for the pending recovery, when recovery completes, then the client can recover access and the resulting shares are re-sealed as specified by the protocol.
- Given a cancelled or expired recovery, when completion is attempted, then it is rejected and no custody material is released.

**FR-13 [INC-4] Custody rotation and rejection notification.** The library shall support share and server-key rotation and notify an owner when a share is rejected.
- Given a rotation request, when the applicable rotation completes, then the active epoch and key identifiers are updated and superseded wrapped share epochs are handled through the ShareStore contract.
- Given a trustee rejects a share, when the rejection is processed, then the configured Notifier informs the owner without logging secret material.

### INC-5: Release readiness and host integration

**FR-14 [INC-5] Host reference application.** The notes application shall demonstrate enrollment, writing a note, closing and reopening a session, and reading the note; it shall run under the simulator with one command and under Confidential Space using documented setup.
- Given the documented simulator prerequisites, when the notes application is started with one command, then a user can enroll, write a note, close, reopen, and read the note.
- Given the documented Confidential Space setup, when the example is deployed, then the same workflow runs against the production adapters.

**FR-15 [INC-5] Production trust-profile build check.** The web build tool shall generate a module from `trust-profile.json` and fail a production-build check if development trust anchors are present in the production bundle.
- Given a production profile and build, when the profile tool runs, then it emits the generated module and the production bundle contains no simulator anchors.
- Given a profile or bundle containing a development anchor, when the production check runs, then the build fails.

**FR-16 [INC-5] Host integration documentation.** A second host project shall be able to integrate using the README without needing to read the normative security specification.
- Given the published README and required host configuration, when a host follows the documented integration steps, then it can configure the required interfaces and run the reference workflow without implementing cryptography.

## Non-Functional Requirements

**NFR-1 [INC-1 onward] Normative security architecture.** The security architecture identified in `PROJECT.md` is the controlling specification for security design and implementation. Requirements and implementation shall not weaken it; traceability shall connect its invariants to tests.
- Given any security-relevant requirement or implementation, when it is reviewed and tested, then its applicable normative invariants are traceable to passing tests and there are no unresolved traceability `GAP` rows at release.

**NFR-2 [INC-1 onward] No inbound TEE connections.** The workload shall make no inbound network connections and shall retrieve work by queue pull.
- Given a workload running in the simulator or Confidential Space, when it communicates with clients or infrastructure, then it receives work through queue pull and exposes no inbound service endpoint.

**NFR-3 [INC-1 onward] Key and secret isolation.** Per-client server keys shall never be stored. Session context, logs, fixtures, and pull-request text shall not expose secrets. Secret values shall use the redacted `Secret` wrapper and explicit wiping where specified.
- Given a normal, error, or debug execution, when logs, fixtures, or request text are produced, then they contain no secrets, keys, shares, nonces, ciphertext, payloads, or request bodies.
- Given a secret wrapper, when it is represented or explicitly wiped, then its representation is redacted and its wipe operation clears its mutable secret buffer to the extent supported by the runtime.

**NFR-4 [INC-1 onward] Cryptographic construction and dependencies.** HPKE shall use RFC 9180 Base mode only; key agreement, KDF, and cryptographic primitives shall not be hand-rolled. Cryptographic dependencies shall be limited to the allow-list in `framework.yaml`, pinned by exact version and hash, with an ADR and Security Architect sign-off for additions or replacements. Forbidden dependencies in `framework.yaml` shall not be used.
- Given a dependency manifest and built packages, when dependencies are checked, then no forbidden or unapproved cryptographic dependency is present and every cryptographic dependency has an exact version and hash pin.
- Given an attempted security implementation, when it performs key agreement, KDF, or HPKE, then it delegates to an approved audited library and uses HPKE Base mode only.

**NFR-5 [INC-1 onward] Independent verification and fail-closed behavior.** Client-side attestation verification shall be independent of server enforcement, and no build may include a verification-skip flag.
- Given any supported build configuration, when it is built and its verification controls are inspected, then attestation verification is enabled and no skip-verification option exists.

**NFR-6 [INC-1 onward] Package isolation and portability.** The simulator shall never be a dependency of `teecustody` or any client package. The TypeScript core shall contain no DOM, `fetch`, or storage dependency; platform capabilities shall enter through interfaces.
- Given each published package's dependency graph and TypeScript core sources, when checked, then the simulator is absent from production dependency graphs and the core has no DOM, `fetch`, or storage dependency.

**NFR-7 [INC-1 onward] Canonical wire interoperability.** Both implementations shall encode and decode the CDDL-defined wire format as canonical CBOR and pass the same simulator-generated vectors. A wire-format change shall update the `proto` string and regenerate vectors in the same change.
- Given the checked-in wire vectors, when Python and TypeScript suites run, then both implementations produce and consume byte-for-byte conformant results.
- Given a wire-format change, when its change is proposed, then the protocol identifier and vectors are updated together and both suites pass.

**NFR-8 [INC-1 onward] Structured, allow-listed logging.** Python and TypeScript logs shall be structured and limited to the fields `client_id`, `request_id`, `session_id`, `prekey_id`, `epoch`, timestamps, and outcome codes.
- Given success and failure paths, when logs are emitted, then they use structured JSON-compatible output with only the allow-listed fields and no secret or request content.

**NFR-9 [INC-1 onward] Code quality and type safety.** Python shall target Python 3.12 or later and satisfy the configured Ruff and strict mypy checks. TypeScript shall use TypeScript 5.x and satisfy configured ESLint, Prettier, and strict TypeScript checks without `any` in packages.
- Given a clean checkout, when the configured lint and typecheck commands run, then all checks pass.

**NFR-10 [INC-1 onward] Test coverage and security review.** New-code line coverage shall be at least 80%; security-relevant paths shall have 100% coverage, including a negative test for every attestation-check branch. High or Critical residual security risk requires human acceptance; High-or-higher findings block merge.
- Given a change to security-relevant code, when its coverage and review gates run, then every branch is covered and all applicable security findings are resolved or the change is blocked.
- Given a release candidate, when the security review is performed, then no unaccepted High or Critical residual risk remains.

**NFR-11 [INC-1 onward] Simulator-first CI and production smoke tests.** Every change shall run the full test suite against the simulator without cloud credentials. A real Confidential Space CI job shall run on a schedule and before release; from INC-3 onward each increment shall include its specified real-environment smoke run.
- Given a clean checkout without cloud credentials, when the configured test command runs, then Python, TypeScript, and cross-implementation vector tests run against the simulator.
- Given a scheduled run or release candidate, when the real-environment job runs, then the Confidential Space smoke tests execute.

**NFR-12 [INC-5] Reproducible signed workload images.** Workload images shall be reproducibly built and signed.
- Given the same pinned source and build inputs, when independent clean builds run, then they produce the same image digest and the release image has a verifiable signature.

**NFR-13 [INC-5] Release completeness.** The v1.0.0 release shall include all eleven deliverables defined by the normative security specification, complete traceability without `GAP` rows, a working example, host integration documentation, and a passed pre-merge security review.
- Given a v1.0.0 release candidate, when its release checklist is evaluated, then every stated deliverable and acceptance condition is satisfied.

## Security Requirements

These requirements capture the structural controls needed by the threat model. As of Security Architect re-review 2 (2026-09-29), every SR has a designed mitigation in `docs/ARCHITECTURE.md` and ADR 0004–0008, and findings F-1..F-5 are closed. SR-6 attribution fields follow D-007 (H-1); aggregate `count` follows D-012. The SR-2 recovery admission hook follows D-011 (INC-4). These requirements do not approve any change to normative wire or security constraints. Authn/authz model changes require human escalation under PROCESS.md §8.

**SR-1 [INC-1 onward] Independent authentication and identity at boundaries.** The reference gateway remains an unauthenticated, untrusted ciphertext relay; do not add host-provided gateway caller authentication or route authorization. Route IDs and caller-supplied identities are non-authoritative routing hints, never proof of identity or authorization. Clients independently authenticate workload identity through attestation verification and the authenticated protocol. The workload shall accept client operations only after authenticated protocol checks and resolve identity from authenticated protocol state, not route IDs. Each production service adapter shall authenticate the workload using its platform identity.
- Given arbitrary, altered, or cross-client route IDs at the reference gateway, when ciphertext is relayed or polled, then route possession does not establish identity or authorize a workload operation; independent client attestation and authenticated protocol checks remain required.
- Given missing, invalid, expired, or mismatched workload attestation, client protocol authentication, or production workload service identity, when the corresponding verifier or adapter boundary is reached, then the check fails before trust establishment, operation dispatch, or protected service access.
- Test description: integration-test gateway routes without caller credentials and verify the gateway only performs bounded ciphertext relay, with route IDs treated solely as routing hints. Test clients against altered/missing workload attestation and authenticated protocol data; test workload dispatch to ensure route IDs cannot substitute for authenticated identity; verify production-adapter calls fail without the workload service identity. Exercise configured rate, size, and polling limits as specified by SR-4.
  - Token JWS (ADR 0009), in addition to the ADR's own test list:
    - Discovery `issuer` differs from the profile → `UNTRUSTED_SIGNER`.
    - `jwks_uri` origin differs from `jwks_origin` → `UNTRUSTED_SIGNER`. Cover `http:`, a different port, userinfo, the suffix host `https://www.googleapis.com.evil.test`, and a path-only difference that still passes.
    - A cross-origin redirect on either fetch → `UNTRUSTED_SIGNER`.
    - Oversized or non-JSON discovery/JWKS documents → `UNTRUSTED_SIGNER`.
    - Candidate filtering: matching `kid` with `kty` EC, `use` `enc`, `alg` `RS384`, missing `n`/`e`, or a duplicate `kid` → `UNTRUSTED_SIGNER`.
    - Every header-rule failure asserts the Fetcher was never called.
    - A production profile with `http:` discovery/JWKS URLs, and a development profile with non-loopback `http:` URLs, are rejected by `parseTrustProfile`.
  - Image signer threshold (D-016, T-22), all with the `image_digest` on the allow-list:
    - (a) `signers_required` distinct matching `key_id`s → accept.
    - (b) One fewer → `UNTRUSTED_SIGNER`.
    - (c) The same matching `key_id` repeated `signers_required` times counts once → `UNTRUSTED_SIGNER`.
    - (d) Unknown `key_id`s are ignored and do not count.
    - (e) A matching `key_id` whose `signature_algorithm` differs from the profile key's `algorithm`, or is outside the allowed set, does not count.
    - (f) An uppercase-hex, 63- or 65-character, or `sha256:`-prefixed `key_id` does not match.
    - (g) An entry with a missing or non-string `key_id`/`signature`/`signature_algorithm` is skipped.
    - (h) `image_signatures` absent → `CLAIM_MISSING`; not an array → `CLAIM_MISMATCH`.
    - (i) `parseTrustProfile` rejects a signer entry that is not exactly `{key_id, algorithm}`, a `key_id` that is not exactly 64 lowercase hex characters, a duplicate `key_id`, or an `algorithm` outside the allowed set.
    - The profile tool derives each `key_id` as SHA-256 of the signer's SPKI DER at build time. Its test uses a known SPKI and expected hex, and it never accepts a caller-supplied `key_id`.
    - The client never calls `verifySignature` for image signatures.
    - The simulator issuer lists only `key_id`s whose signatures it verified.

**SR-2 [INC-1 onward] Centralized authorization and tenant isolation.** A single boundary policy shall authorize the authenticated principal, operation, resource owner, epoch, and pending recovery state before dispatch or backend access. Adapters shall enforce tenant-scoped resource keys as defense in depth. Host application authorization remains host-owned and shall not be implied by successful library authentication.
- Given an authenticated client or service principal, when it requests an operation or resource outside its tenant, role, epoch, or pending recovery, then the central policy rejects it before handler invocation or secret access.
- Given an `open_session` whose AAD `client_id` is B but whose `cs` belongs to A, when the TEE reconstructs and checks `kcv`, then verification fails, no session or principal is established, and no handler runs.
- Given a `recover_start` naming any `owner_id`, when it is accepted, then that `owner_id` is treated only as the subject (never as an authenticated principal), the owner's existing client(s) and the trustees are notified, and the number of pending recoveries per owner stays within the configured bound. Possession of a `recovery_id` alone never authorizes release or completion.
- Test description: table-driven authorization tests cover every operation class and cross-client resource access; adapter contract tests attempt mismatched owner/client IDs, epochs, and recovery IDs and assert no read, write, or share release occurs. Include the cross-client `open_session` case above, a `recover_start` for another owner asserting the owner-notification event and the per-owner pending bound, and a `release_share` call by a non-nominated client that knows a valid `recovery_id`. Recovery admission hook (INC-4, D-011; T-21), with a hook configured:
  - A `recover_start` whose `trigger_evidence` the hook rejects returns a stable rejection. It creates no pending recovery, sends no notification, and does not count toward `MAX_PENDING_RECOVERIES_PER_OWNER` or `RECOVERY_STARTS_PER_OWNER`: after more rejected starts than the bounds, an admitted start for the same owner still succeeds.
  - The hook receives only `owner_id` and the opaque `trigger_evidence`.
  - A hook exception or timeout fails closed as a rejection.
  - `trigger_evidence` never appears in logs, audit records or errors (sentinel scan).
  - With no hook configured, behavior equals the pre-D-011 bounds.

**SR-3 [INC-1 onward] Validation at every trust boundary.** Every external or less-trusted boundary shall apply strict typed/schema validation and configured size, depth, count, and time bounds before domain processing. Canonical wire parsing shall follow the normative CDDL and reject noncanonical, unknown-invalid, truncated, or oversized values without fallback. Cloud adapter responses, simulator inputs, CLI arguments, host hooks, configuration, and browser capability responses shall be validated before use.
- Given malformed, noncanonical, out-of-range, oversized, or structurally inconsistent input at any boundary, when it is parsed, then processing fails closed before state mutation or expensive unbounded work.
- Test description: boundary-focused negative tests and fuzz/property tests exercise every parser/adapter contract, including truncated CBOR, excessive nesting/length/count, invalid IDs/cursors/configuration, and malformed cloud/browser responses; assert stable errors and unchanged state. A static rule (semgrep / eslint no-restricted-imports) fails CI if any module outside the `wire` packages imports or calls the CBOR library's decode functions directly.
  - TypeScript codec (ADR 0010):
    - The shared vectors include the integer boundaries 2^53−1, 2^53, 2^64−1, −2^64 (valid) and 2^64, −2^64−1 (invalid).
    - The Python and TypeScript codecs agree on every case in the ≥ 500-case differential corpus.
    - Before any INC-2 task decodes untrusted queue or gateway input, a scheduled CI job runs ≥ 100,000 mutation-fuzz cases of `decodeCanonical`, seeded from the valid vectors and the corpus. It asserts that decoding only returns a value or throws `WireError`, that accepted inputs re-encode byte-identically, and that the time per input stays bounded.

**SR-4 [INC-1 onward] Abuse and resource controls.** Public and service ingress shall enforce centralized rate, concurrency, payload-size, polling, and expensive-operation budgets with bounded queues and retries. Limits shall not weaken protocol verification or silently drop custody state transitions.
- Given a caller exceeds an ingress or operation budget, when further requests arrive, then excess work is rejected or delayed using a bounded policy before it exhausts shared service capacity.
- Test description: deterministic load tests exceed each configured route, queue-pull, token-verification, and recovery-operation budget; assert bounded resource use, rejection semantics, no state corruption, and continued service for in-budget callers.

**SR-5 [INC-1 onward] Data protection at rest and in transit.** Protected records, shares, keys, and browser vault values shall use the storage protections already specified by the normative architecture. Every networked production adapter shall use authenticated encrypted transport and validate the expected service identity; plaintext fallback and unapproved redirects are rejected.
- Given data is written to a storage adapter or sent over a production network adapter, when persistence or transport occurs, then only the specified encrypted/sealed representation is persisted and transport is authenticated and encrypted without downgrade or cross-origin redirect.
- Test description: production-adapter contract tests inspect persisted fixtures for ciphertext/sealed values and absence of plaintext keys/records; transport tests fail on plaintext endpoints, invalid service identity, TLS errors, and redirects to an untrusted origin. Verify browser persistence contains only ciphertext. Production startup rejects any non-`https` endpoint in configuration. A static rule fails CI on TLS-verification overrides (e.g. `verify=False`, insecure channel credentials, `rejectUnauthorized: false`).

**SR-6 [INC-1 onward] Security audit.** The following events shall produce protected, append-only audit records: authenticated-principal authorization denials, recovery approvals/rejections, terminal recovery transitions, key/epoch rotation, and security-relevant configuration or release events. The workload writes its records to a create-only, retention-locked bucket in an audit project separate from the workload project. Operator actions are attributed by IAM principal through Cloud Audit Logs: Admin Activity, plus Data Access for Cloud KMS. These are exported through an aggregated sink that workload-project administrators cannot modify (spec §7.3, §12). The release process records the spec §12 sign-offs in the same protected sink. Authentication failures that occur before a principal exists are recorded as per-interval aggregate counters, not as per-event objects. Workload audit fields stay within the configured allow-list. Under D-007 (H-1), audit records only, never general logs, may also carry the role-qualified fields `actor_client_id`, `subject_client_id` and `recovery_id`, sourced as in ARCHITECTURE "Audit record fields". `AGGREGATE` records may carry a non-negative integer `count` of occurrences in the interval (D-012). No other record class carries it.
- Given a security-relevant workload event occurs, when the operation succeeds or is rejected, then exactly one audit outcome is durably recorded. Its identifiers come from authorized context, it contains no secret or payload data, and audit failure follows the fail-closed policy in ADR 0005.
- Given an operator changes KMS IAM, the WIP condition, the digest allow-list or the signer set, or a non-attested principal attempts KMS decrypt, when the platform audit entry is written, then it lands in the protected sink attributed to the IAM principal, and workload-project owners cannot delete, overwrite or re-route it.
- Test description: integration-test each listed workload event for exactly one correctly correlated outcome, append-only and create-if-absent behavior (a pre-existing object causes an alert, not an overwrite), configured retention/access controls, and rejection of records containing fields outside the allow-list or secret markers. Flood pre-authentication failures and assert only bounded aggregate records, each with a `count` equal to the injected occurrences for its outcome and interval. `AuditSink` rejects `count` on any non-`AGGREGATE` record. Scheduled real-GCP tests (spec §13.6): KMS audit logs land in the protected sink, and a workload-project owner is denied when trying to delete audit objects or modify the sink.

**SR-7 [INC-1 onward] Secret provisioning and lifecycle.** Secrets shall enter production components only through the approved platform secret mechanism; access, rotation, revocation, and development/production separation shall be structurally enforced. Secret values remain transient where specified and are excluded from logs, errors, fixtures, context, and persisted records.
- Given an unauthorized identity requests a secret or a development secret is presented to production, when the secret boundary evaluates the request, then access is denied; authorized rotation/revocation takes effect without exposing secret bytes.
- Test description: secret-provider integration tests cover authorized and unauthorized principals, rotation and revocation, simulator-to-production separation, redacted representations, wipe behavior, and sentinel scans of logs/errors/fixtures for injected secret values.

**SR-8 [INC-1 onward] Least privilege for service identities.** Workload, gateway, simulator, CI, release/signing, and each production adapter identity shall have a separately documented minimum permission set. The workload may access only required queues, client-scoped stores, and KMS operations; signing credentials shall not be available to ordinary build/test jobs.
- Given each service identity is deployed, when its permissions are evaluated and exercised, then required operations succeed and unassigned resource/action access is denied.
- Given any principal that holds a role on the workload or gateway project, when Audit Project IAM is evaluated, then it holds at most:
  - (i) the attested workload identity's `storage.objects.create`, conditioned to the `event/`, `alert/` and `aggregate/` prefixes of the workload audit bucket; and
  - (ii) the read-only audit-reader role.
  
  It holds no admin, IAM-set, bucket-update, retention, delete, or sink/log-bucket permission there. Release owners and signers hold create-only on `release/` and no workload-project admin role.
- Test description: automated IAM policy checks compare deployed roles with reviewed allow-lists; negative integration tests attempt cross-tenant storage/KMS/queue operations and build-job access to release signing credentials. The policy check evaluates the cross-project rule above exactly as written, including a fixture where a workload-project admin is granted `storage.buckets.update` in the Audit Project, which must fail the check. It also asserts that no principal holds both custody-key administration and decrypt (spec §7.3). While FACTS F-16 is unconfirmed (T-22), the policy check fails if the custody-key WIP attribute condition lacks the `submods.container.image_digest in ALLOWED_DIGESTS` clause. A signature-only condition is rejected.

**SR-9 [INC-1 onward] Dependency admission.** Runtime and build dependencies shall satisfy the OSI license, 18-month release, configured allow-list/forbidden-package, exact crypto version/hash, and scanner requirements in `framework.yaml`. Crypto dependency additions or replacements require the specified ADR and Security Architect sign-off before lock-file approval.
- Given a dependency graph includes an unapproved, forbidden, stale, unlicensed, or incorrectly pinned package, when CI evaluates it, then the build fails before packaging or release.
- Test description: CI fixtures introduce one violation of each dependency rule and assert the dependency-policy job fails; verify configured dependency, secret, static, and image scanners run and publish reviewable results.

**SR-10 [INC-5] Release artifact authenticity.** Workload image and client release signing shall use controlled signing identities, protected key custody, separation from ordinary build execution, and independent signature verification. Reproducible builds shall be tied to the verified source and dependency inputs.
- Given an image or package is built from approved inputs, when it is released, then its signature verifies under the approved release identity; an unsigned, altered, or incorrectly signed artifact cannot be deployed or published.
- Given a CI-built artifact, when each release signer is asked to sign, then that signer has independently rebuilt the artifact from the approved source commit outside CI and signs only if the reproduced digest matches. The signer's verification record states the reproduced digest.
- Test description: release-pipeline tests verify valid signatures and reject unsigned, tampered, wrong-key, single-identity-duplicate, and unapproved-provenance artifacts; access-control tests prove ordinary CI jobs cannot sign or retrieve signing keys. Release-procedure test: an artifact whose CI digest differs from an independent reproduction is not signed and cannot be deployed.

**SR-12 [INC-1 onward] Security alerting (spec §12).** Each of the following events shall raise an alert through a designed path, and no alert shall carry a token, key, share or payload:
  - a KMS decrypt denied by the WIP condition (log-based alert on the platform audit sink);
  - a `kcv` mismatch or a rejected trustee share (distinct, alert-classified workload security-event outcome codes);
  - a debug-mode token seen by a client (an injected Core security-event capability with a distinct reason code).

A pre-key burn rate above a configured threshold SHOULD also alert (T-17).
- Given any listed event occurs, when it is detected, then exactly one alert-classified event reaches the configured sink containing only allow-listed fields, and the triggering operation still fails closed.
- Test description:
  - Simulator: corrupt a stored `kcv` and assert the session aborts and the alert event is emitted.
  - Simulator: corrupt one trustee share and assert rejection by index plus the alert event.
  - Simulator: use `teecustody-sim token --alter dbgstat=enabled` and assert Core rejects the bundle and calls the injected security-event sink with the debug-mode reason code and no token content.
  - Scheduled real-GCP (spec §13.6): a decrypt by a non-attested principal produces a denied KMS entry in the protected sink and fires the alert.
  - Cap scope (simulator): send more than `AUDIT_ALERT_CAP` anonymous `kcv` mismatches over distinct `subject_client_id`s within one interval, then, in the same interval, trigger `TRUSTEE_SHARE_REJECTED`, `AUDIT_WRITE_CONFLICT` and `PREKEY_BURN_HIGH`, plus one further `kcv` mismatch for a previously unseen subject. Assert:
    - each of the three non-pre-principal alerts is written individually (the cap and dedup apply only to pre-principal alert-class events);
    - exactly one `ALERT_CAP_REACHED` is written, and it does not count against the cap;
    - the over-cap `kcv` mismatch appears in that interval's `KCV_MISMATCH` aggregate;
    - total alert objects are ≤ `AUDIT_ALERT_CAP` + 1 + the non-capped alerts.
  - `POST /security-events` (notes-app): only the closed code enum in a body of at most 64 bytes is accepted; anything else returns 400 and logs nothing; the per-source and global limits hold; the log entry contains only `event`, `outcome`, `timestamp`. Core emits `ATTESTATION_DEBUG_MODE` only when the signature and issuer checks pass; a debug-mode token with a bad signature emits nothing.

**SR-13 [INC-2 onward; notes-app from INC-3] Web code delivery (spec §10.3).** `@teecustody/core` and `@teecustody/web` shall run under a strict Content-Security-Policy (no `eval`/`new Function`, no inline script). The reference web client shall meet all four of these requirements, and the host integration documentation shall state them as required, together with the residual limit that the origin remains trusted for code delivery (T-19):
  - SRI on every script;
  - a CSP with `script-src` restricted to hashed or SRI-tagged resources and no inline scripts;
  - no third-party scripts on pages that handle keys;
  - a reproducible build that publishes a hash for every shipped bundle.
- Given the reference web client is built and served, when a browser loads it, then every script is SRI-tagged and the enforced CSP produces no violations across enroll → put → close → open → get.
- Test description:
  - A headless-browser test runs the notes-app flow with the strict CSP in enforce mode and asserts zero CSP violation reports.
  - A static check asserts every script tag carries `integrity` and no third-party script origin appears on key-handling pages.
  - A bundle scan asserts no `eval`/`new Function` in the shipped `@teecustody/*` code.
  - Two clean builds produce identical bundle hashes that match the published manifest.
  - `teecustody-profile csp` rejects any `--connect` value that is not a single exact `https://host[:port]` origin (loopback only with a development profile). It also rejects wildcards, schemes other than `https`, quotes, semicolons, whitespace and CSP keywords, and never emits `'self'`, `'unsafe-inline'`, `'unsafe-eval'` or `'strict-dynamic'` in `script-src`. Unit fixtures cover each rejection.
  - `teecustody-profile check-html` fails on every violating fixture: a missing or mismatched `integrity`, an inline script, an inline handler, a `javascript:` URL, or a third-party origin.
  - `connect-src` includes both the discovery origin and the `jwks_uri` origin that the production trust profile requires.

**SR-11 [INC-1 onward] Non-disclosing errors.** Untrusted callers shall receive only stable public error categories and sanitized messages. Provider exceptions, tokens, payloads, credentials, and secret-bearing internal causes shall not cross the boundary or be written to logs.
- Given a request triggers parser, authentication, authorization, crypto, or backend failure, when its error is returned or logged, then only the documented category and allow-listed fields are observable.
- Test description: inject sentinel secrets and provider exception text into each error class; assert responses and captured logs contain neither the sentinel nor internal causes and match the stable error schema.

## Defaults

- [DEFAULT] The human approved the `PROJECT.md` INC-1 through INC-5 sequence as the baseline. The `framework.yaml` increment mapping may be reconciled later; this does not block G1.
- [DEFAULT] The simulator is the default environment for development and CI; no cloud credentials are needed for its test suite.
- [DEFAULT] Browser support is limited to environments that provide the required WebAuthn PRF, IndexedDB, and WebCrypto capabilities. Unsupported environments fail closed; no alternate share-storage mechanism is implied.
- [DEFAULT] Host-supplied settings are `AUDIENCE`, `TOKEN_TYPE`, digest allow-list, signer keys, `SIGNERS_REQUIRED`, and trustee `k`/`n`. Other parameters use the defaults defined by the normative specification; this requirements document does not invent their values.
- [DEFAULT] Python memory zeroisation is not guaranteed. The implementation applies the specified secret-handling hygiene, and this runtime limitation is documented as residual risk rather than treated as a release blocker by itself.
- [DEFAULT] The documented normative security architecture takes precedence over any conflicting or less-specific requirement here. Any proposed deviation follows the framework's human-only constraint-deviation decision process.

## Human Questions

- [HUMAN] **Before INC-4, not G1:** If the proposed Python Feldman VSS implementation over libsodium Ristretto255 requires a constraint deviation or a cryptographic dependency change, will the human approve that specific deviation after Security Architect review? No approval is implied by this requirements document.

## Out of Scope

- Mobile share vaults and transports; the platform-agnostic TypeScript core must not block a later mobile package.
- Attestation for clouds or TEEs other than Google Cloud Confidential Space.
- Host application authentication or mapping a `client_id` to a host account; host mapping is supplied through the Directory backend and enrollment hook.
- A hosted queue gateway product; only a reference gateway in `examples/` is included.
- A general-purpose cryptography library, database, queue, or KMS product.
- A library-provided host-user identity system or application-specific authorization policy.

## Increment Ordering

1. **INC-1: Attestation foundation.** Put the normative wire/spec foundation in place, implement simulator issuer and launcher, and implement Python attestation and TypeScript verification with negative vectors. This is the smallest observable slice exercising the simulator-to-client trust flow.
2. **INC-2: Encrypted channel and browser client.** Add pre-keys, bundles, HPKE sessions, authenticated framing and replay protection, in-memory queue, reference gateway transport, and WebAuthn PRF vault. Deferred from INC-1 because token trust is the prerequisite for safe channel establishment.
3. **INC-3: Enrollment, custody, records, and production adapters.** Add enrollment and sessions, 2-of-2 custody, key-check values, envelope encryption, record storage, Cloud KMS and GCP adapters, and the notes example. Deferred until the authenticated channel exists so the end-to-end custody workflow can be tested over it.
4. **INC-4: Trustee recovery and rotation.** Add identity-binding keys, Feldman VSS, trustee configuration and release, recovery lifecycle, rotation, and notifications. Deferred because it builds on established custody and introduces additional cryptographic and recovery risk.
5. **INC-5: Release readiness.** Add hardened base image, reproducible builds, signing, build-separation checks, complete traceability and documentation, and v1.0.0. Deferred until functional flows exist so release hardening validates the complete product.

Each increment's acceptance tests shall pass in CI against the simulator. Beginning with INC-3, the increment shall also include the real Confidential Space smoke test specified by `PROJECT.md`.
