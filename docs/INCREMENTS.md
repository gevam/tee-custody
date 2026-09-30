# Increments

The sequence and scope below preserve the approved INC-1 through INC-5 baseline in `docs/REQUIREMENTS.md`. No additional deliverable or product capability is introduced. Every increment ships with simulator-based acceptance tests; from INC-3 onward it also includes that increment's real Confidential Space smoke run. Common gates apply throughout: configured lint/type checks, at least 80% new-code line coverage, 100% security-path coverage, dependency/security scans, no secrets in artifacts, and no unresolved High/Critical finding.

## INC-1: Attestation foundation

**Goal:** Establish the first observable vertical slice from local launcher through workload token acquisition to independent TypeScript client verification.

**Scope and acceptance criteria:**

- FR-1: Python workload obtains and refreshes an audience-bound token from the simulator launcher socket using the identity-key hash nonce; workload has no inbound endpoint.
- FR-2: TypeScript verifier checks explicit trust profile and every required token predicate independently; valid token passes and each altered/missing check fails closed.
- FR-3: Simulator starts without cloud credentials, exposes launcher socket and loopback OIDC discovery/JWKS, enforces `SIGNERS_REQUIRED`, emits requested negative cases, and writes cross-language vectors to the requested directory.
- NFR-1, NFR-2, NFR-4, NFR-5, NFR-6, NFR-7, NFR-8, NFR-9, NFR-10, and NFR-11 apply to this slice as relevant: simulator isolation, no verification bypass, canonical shared vectors, approved dependencies, redacted allow-listed logging, test/lint/type gates, negative branch coverage, and credential-free CI.

**Vertical path:** Simulator config/issuer and launcher socket -> Python Launcher port and workload attestation lifecycle -> token/vector output -> TypeScript Core trust-profile verifier -> shared positive and negative tests. Each layer is exercised once; no channel, custody, cloud adapter, or host application is included.

- SR-12 (client part): `verifyAttestation` reports `ATTESTATION_DEBUG_MODE` to the required `SecurityEventSink` when signature and issuer pass and `dbgstat` is wrong. `teecustody-sim token --alter dbgstat=enabled` drives the test with an in-memory sink and asserts that no token content is reported.

**Contracts introduced:** `Launcher.get_attestation_token`; simulator discovery/JWKS and negative-token/vector CLI contracts; `verifyAttestation` (including the `events: SecurityEventSink` parameter); `SecurityEventSink`/`SecurityEvent`; TrustProfile/ExpectedAttestation/VerifiedAttestation and AttestationError; normative canonical-CBOR/vector/`proto` binding. INC-1 CONTRACT_ISSUE rulings (2026-09-30) also introduce: `VerifierDeps`, `Crypto.verifySignature` (RSA only), `AttestationError.check`, the extended trust-profile fields, `teecustody-sim serve`, RS256-pinned JWS handling (ADR 0009), and the project-owned TypeScript CBOR codec (ADR 0010).

**Out of scope:** FR-4 onward except shared constraints. No WebAuthn vault, session channel, enrollment, custody, cloud production adapters, recovery, or notes app.

## INC-2: Encrypted channel and browser client

**Goal:** Add an authenticated request/response path over queue relay and browser-held encrypted client share.

**Scope and acceptance criteria:**

- FR-4: valid signed pre-key bundle opens an HPKE RFC 9180 Base session; authenticated sequence framing succeeds; authentication failure, invalid sequence, and replay reject before dispatch.
- FR-5: browser request and response are relayed to the correct workload/client via queue publication and pull; no inbound workload endpoint.
- FR-6: WebAuthn PRF-derived key wraps the share; IndexedDB persists ciphertext only; missing/unusable PRF fails closed without plaintext persistence or exposure.
- Continue applicable NFR-1 through NFR-11 gates, particularly approved crypto, canonical vectors, package isolation, independent attestation verification, and security-path tests.

- SR-6 / SR-12 (workload, simulator): `AuditSink` port with `InMemoryAuditSink`; pre-principal failures (`Open` failure, unknown/consumed pre-key, stale, replay, bad frame) produce bounded `AGGREGATE` records carrying `count` (D-012); `PREKEY_BURN_HIGH` alert (SHOULD).
- SR-13 (libraries): lint bans and the shipped-output bundle scan for `@teecustody/core`/`web`; a headless-browser harness runs vault and transport under the strict CSP with zero violations (ADR 0008).

**Verification tasks and risks (Wave 0, before any dependent task starts; results recorded in the task report with sources and versions, spec §0 line 13):**

| Id | Verify | Pass condition | If it fails |
|---|---|---|---|
| V-2.1 | **Retired (ADR 0010).** Core and Web use the project-owned canonical CBOR codec delivered in INC-1, and no package depends on `cbor-x`. | — | — |
| V-2.2 | Each target browser honors CSP `script-src` hash sources for external scripts that carry a matching SRI `integrity` attribute | In the headless-browser matrix, a page whose CSP lists only the script's `sha384` hash loads it, and loads nothing else | Record the browser as unsupported, failing closed, in the support matrix next to WebAuthn PRF (PROJECT.md R2). Never add `'self'` or host sources to `script-src`. If this excludes a browser the human expects to support, escalate. |

**Contracts introduced:** signed pre-key bundle and session open; HPKE session-key export boundary; authenticated frame/sequence/replay contract; Queue port and Reference Gateway/Web Transport contracts; WebAuthn PRF and encrypted IndexedDB vault adapter contracts; `AuditSink`/`AuditKey`/`AuditRecord` and the aggregation/cap rules.

## INC-3: Enrollment, custody, records, and production adapters

**Goal:** Support the first persisted per-client host data workflow through authenticated sessions and production-capable ports.

**Scope and acceptance criteria:**

- FR-7: mint opaque client ID, publish public identity/fingerprint, invoke host hook; ignore untrusted client-asserted identity for routing/authorization.
- FR-8: registered handlers receive constrained session context and record operations; built-in names cannot be overridden; secret material is inaccessible through context.
- FR-9: initialize specified 2-of-2 custody and key checks without server-key persistence; envelope-encrypt/read records and remove deleted records according to contract.
- FR-10: all eight backend ports have simulator and production adapters; production Cloud KMS uses attested workload identity and configured Google Cloud services.
- SR-6 / SR-12 (production):
  - `GcsAuditSink` against a create-only, retention-locked bucket in the separate Audit Project.
  - Folder-level audit config and aggregated sink to the locked `platform-audit` log bucket.
  - Log-based alert policies `KMS_DECRYPT_DENIED`, `WORKLOAD_ALERT`, `CLIENT_DEBUG_MODE_TOKEN`, `TRUST_CONFIG_CHANGED`.
  - `KCV_MISMATCH` alert via a corrupted-`kcv` simulator test.
  - Real-GCP §13.6 checks: a denied decrypt lands in the sink and alerts; a workload-project owner cannot delete audit objects or modify the sink.
  - Record the verified audit-log method names and filters.
- SR-13 (notes-app web client): `teecustody-profile manifest|csp|check-html`, SRI on every script, hash-only CSP header from the static host, no third-party scripts, a two-build manifest equality check, the enforce-mode CSP flow test, and the `POST /security-events` route with `BeaconSecurityEventSink`.
- Run the INC-3 Confidential Space smoke test and applicable common NFR gates.

**Contracts introduced:** enrollment and Directory/host hook; operation registration/dispatch and SessionContext (including `LIMIT_EXCEEDED`); KeyWrapper, ShareStore, RecordStore, Directory and remaining production adapter contracts; `GcsAuditSink`; custody/record envelope and epoch contracts; notes workflow integration surface; `teecustody-profile` `manifest`/`csp`/`check-html` CLI; notes-app security-event route.

## INC-4: Trustee recovery and rotation

**Goal:** Add threshold trustee recovery, share release, re-sealing, rotation, and notifications on established custody boundaries.

**Scope and acceptance criteria:**

- FR-11: configure trustees and valid threshold; persist sealed shares and commitments; release only the approving trustee's share for a valid pending recovery; reject unauthorized release.
- FR-12: start and notify, reject completion below threshold, complete with threshold-valid shares and re-seal, and reject cancelled/expired recovery without release.
- FR-13: rotate share/server-key epochs and notify owner of rejection without secret logging.
- Resolve the human question in REQUIREMENTS.md concerning any proposed Feldman VSS/libsodium constraint or dependency deviation before implementing that deviation. Run the INC-4 Confidential Space smoke test and applicable common NFR gates.

- SR-2 / SR-4 (F-5), tested per ARCHITECTURE "Testing strategy":
  - `recover_start` treats `owner_id` as a subject only.
  - It notifies the owner (`RECOVERY_PENDING`) and then the trustees, and cancels the recovery if any notification fails.
  - Per-owner pending and start-rate bounds are enforced atomically in `TrusteeStore`.
  - `recovery_id` never authorizes: release needs a nominated trustee principal, completion needs the matching `RIB_priv`, cancel (`recover_cancel`, D-008) needs the owner principal.
- SR-6 / SR-12: `TRUSTEE_SHARE_REJECTED` alert; recovery, rotation and `set_trustees` intent/outcome records carrying exactly the fields in the ARCHITECTURE "Audit record fields" table (D-007); the static rule that bans a `recovery_id` authorization input. Aggregates carry `count` (D-012; the `AuditSink` contract is updated in INC-2 where aggregates are introduced).
- D-011 / T-21: optional host recovery-admission hook (`Workload.recovery_admission`) over `trigger_evidence`, run before the per-owner bounds, with the tests listed in ARCHITECTURE "Testing strategy" (rejections and failures do not consume the bound; default admits all; fail closed on exception or timeout). The README documents that evidence must be self-verifiable inside the TEE. No wire change: if `spec/wire` does not type `trigger_evidence` as a byte string, raise a CONTRACT_ISSUE.

**Contracts introduced:** trustee configuration and release; recovery state machine and threshold completion (`PendingRecovery`, `RecoveryState`, `create_pending_recovery`, `transition_recovery`); commitment/share verification and re-sealing; rotation/epoch transition; `Notifier.notify(recipient, NotificationEvent)`; `recover_cancel` (reserved name; CDDL payload from `spec/wire`); `client.cancelRecovery`; the audit field set per event type; `RecoveryAdmissionRequest`/`AdmissionDecision`/`Workload.recovery_admission` and the `MAX_TRIGGER_EVIDENCE_BYTES` and `RECOVERY_ADMISSION_DEADLINE` limits.

## INC-5: Release readiness and host integration

**Goal:** Prove the supported host workflow and deliver the hardened, documented, reproducible v1.0.0 release.

**Scope and acceptance criteria:**

- FR-14: notes app enrolls, writes, closes/reopens a session, and reads a note with one simulator command and documented Confidential Space setup.
- FR-15: generate trust-profile module and fail production bundle check on simulator anchors.
- FR-16: a second host integrates via README without implementing cryptography or reading normative security specification.
- NFR-12: independent clean builds from pinned inputs produce the same workload image digest; release signature verifies.
- NFR-13: all eleven normative deliverables, complete traceability with no GAP, example/docs, and passed pre-merge security review are present for v1.0.0.
- Run final scheduled/pre-release Confidential Space smoke, production bundle scan, full simulator suite, configured quality/scanner gates, and required human release approval.

- SR-10 (F-2): the independent signer reproduce-compare-sign procedure for the workload image, Python/npm package files and the notes-app web manifest, including the refusal-on-mismatch test; deploy/publish verification of signatures and verification records; publication from outside CI.
- SR-6 (F-1(c)): two-owner sign-off records under `release/` for allow-list, signer-set, WIP and KMS IAM changes, confirmed in the protected sink. The host README states the SR-13 and client security-event endpoint requirements and the T-19 residual limit.

**Contracts introduced:** host setup/configuration and release workflow; trust-profile generation and production-bundle check; reproducible image build/sign/verify; signer verification-record format and deploy/publish gate; release sign-off record format; final traceability and release checklist.