# ADR 0005: Protected Audit and Secret Lifecycle

## Status

Proposed; amended 2026-09-29 (D-006, Security Architect re-review 1 finding F-1(b)–(e)). Attribution fields remain pending human decision H-1. See Amendments.

## Context

The threat review requires protected append-only audit records with defined failure and retention behavior, and production secret/configuration provisioning and rotation. Existing approved infrastructure includes GCS and Cloud KMS. The configured audit/log allow-list is limited to `client_id`, `request_id`, `session_id`, `prekey_id`, `epoch`, timestamps, and outcome codes. The project cannot add a cloud service or change the normative security architecture.

## Decision

Store immutable per-event audit objects in a dedicated, retention-locked bucket within the existing GCS service. The workload writer is create-only; readers and retention administrators are separate principals. Set and lock an explicit retention duration before production. A state-changing operation writes an intent before mutation and one immutable outcome after resolution, keyed by the stable operation identifier; it is not acknowledged successful until the outcome is durable. Failed appends fail closed and are retried/reconciled idempotently without repeating the state transition. Denials remain denials if audit storage is unavailable.

Audit records remain within the existing non-secret field allow-list. This prevents full attribution of trustee and operator actions because no separate actor identity field is allowed. Do not smuggle identities into unrelated fields or encode unbounded identifiers as outcome codes. Closing T-05 requires a Security Architect and human decision that resolves this field/constraint conflict; until then, do not represent T-05 as mitigated or G3-approved.

Production runtime identity comes from the Confidential Space platform. Existing Cloud KMS operations are the only approved runtime path for key material assigned there; key bytes are not injected into application configuration or exported. Non-secret settings, including production trust profiles, are strictly validated and versioned with the signed release; production startup rejects simulator anchors and unknown or malformed security settings. Configuration changes use the existing reviewed release process, and trust-profile/signer-set changes retain their human-approval requirement. Rotation provisions a replacement version, switches and verifies consumers, then revokes the old version. Simulator keys remain development-only. No Secret Manager, new secret service, or identity system is introduced.

## Consequences

The audit bucket requires a dedicated retention configuration and separate IAM roles but no new cloud service or storage engine. Event operations need stable IDs and idempotent reconciliation. Retention cannot be shortened after lock. Secret access, rotation, and revocation tests must use platform identities and Cloud KMS-compatible test doubles. T-11 is addressed by design, subject to tests. T-05's storage, append-only, failure, and retention controls are specified, but its required attribution remains an unresolved contract issue.

## Alternatives considered

- Use ordinary mutable logs or an unlocked bucket: rejected because records could be rewritten or deleted before retention expiry.
- Add Cloud Logging, Secret Manager, or a new audit service: rejected because the task forbids new cloud services.
- Add actor identities to the audit allow-list silently: rejected because it changes an approved constraint and requires human resolution.
- Persist secret values in environment configuration: rejected because platform identity and existing Cloud KMS operations provide the approved path without distributing static credentials.

## Amendments

- 2026-09-29 — **F-1(b)–(e), D-006. Workaround or refactor: refactor.** The original rejection of Cloud Logging was wrong. Spec §7.3 line 201 ("KMS audit logs MUST be enabled and exported to a sink that project administrators cannot modify"), §12 line 302 ("logged to the protected audit sink") and §13.6 ("KMS audit logs land in the protected sink") make platform audit logging normative, and spec §0 line 12 says the spec wins. Operators never authenticate to the workload, so IAM-principal attribution in Cloud Audit Logs is the only way operator actions can be attributed. No local workaround exists. The "Add Cloud Logging" alternative is therefore withdrawn as a rejection. The following decisions supersede the corresponding parts above; details are in ARCHITECTURE "Protected audit".
  1. **Platform audit path (b).**
     - Admin Activity logs, plus Data Access logs for `cloudkms.googleapis.com` and `sts.googleapis.com`, enabled at folder or organization level so that project owners cannot disable them.
     - A folder/organization-level aggregated sink (`includeChildren`) to a locked-retention `platform-audit` log bucket in a separate **Audit Project** whose administrators are disjoint from the workload project's.
     - This is platform configuration. The workload never calls Cloud Logging, so spec §11 line 290 egress is unchanged.
  2. **Release events (c).** Changes to the digest allow-list, signer set, WIP condition or KMS IAM require signed sign-off records from two named owners, written create-only to `release/` in the audit bucket before the change is applied. The resulting Admin Activity entry lands in the sink. Signer verification records (ADR 0006) go to the same place.
  3. **Bucket isolation and create-if-absent (d).**
     - The workload audit bucket moves to the Audit Project.
     - Writes use `ifGenerationMatch=0` through a new `AuditSink` port (`GcsAuditSink`, `InMemoryAuditSink`).
     - A precondition conflict is never an overwrite. It is treated as "present" and raises an `AUDIT_WRITE_CONFLICT` alert.
     - The writer keeps create-only permission. We accept rare false-positive alerts after ambiguous retries rather than grant read.
  4. **Pre-principal aggregation (e).**
     - Failures before a principal exists become one `AGGREGATE` object per outcome code per instance per interval.
     - Pre-principal alert-class events (a `kcv` mismatch is reachable anonymously via `open_session`) are written as the first occurrence per `(outcome, client_id)` per interval, capped at `AUDIT_ALERT_CAP` per interval.
     - Storage is bounded regardless of anonymous traffic.
  5. **Attribution fields (a): PLACEHOLDER, pending H-1.** `actor_client_id`, `subject_client_id` and `recovery_id` are not designed. A numeric `count` on aggregates is also outside the current allow-list (`client_id`, `request_id`, `session_id`, `prekey_id`, `epoch`, timestamps, outcome codes), so it is held with H-1. Until then, aggregates record presence (≥ 1) only.
  - Consequences:
    - Cloud Logging and Cloud Monitoring (log-based alerts, ADR 0007) become required production configuration, and the deployment gains a third project.
    - Real-GCP §13.6 tests must show that a workload-project owner cannot delete audit objects or modify the sink.
    - Residual: principals above the folder can alter sink routing (T-05 Low). Retention lock still protects records already written.
    - Aggregates in memory are lost on instance crash mid-interval.
- 2026-09-29 — **F-1(a), H-1 decided by the human (D-007).** This supersedes item 5 of the previous amendment and the "Add actor identities" rejection above. It is not a constraint-deviation. Details are in ARCHITECTURE "Audit record fields".
  1. **New fields.** Audit records (not general logs) carry:
     - `actor_client_id`: the authenticated principal, from session state; absent when no principal exists;
     - `subject_client_id`: the owner of the targeted resource, from the stored record the policy authorized against (or the HPKE-authenticated AAD for pre-principal `kcv` events);
     - `recovery_id`: taken from the loaded `PendingRecovery`, never from the received value.
     
     The plain `client_id` is no longer used in audit records. None of these values is ever copied from the payload.
  2. **Field set per event type.** ARCHITECTURE defines exactly which fields each event carries: denials, `set_trustees`, trustee release/decline/share-rejected, recovery start/complete/cancel/expire, rotations, and alerts. Unauthenticated rejections that an attacker could repeat without limit (`recover_start` over bound, `recover_complete` rejected) become `AGGREGATE` records, so storage stays bounded.
  3. **Structural rule: `recovery_id` never authorizes.**
     - The authorization policy decides on `(principal, operation, loaded resource)` and has no `recovery_id` parameter.
     - The received ID is only a lookup key.
     - Unknown and unauthorized IDs return the same `NOT_AUTHORIZED`.
     - A semgrep rule and a review-checklist item enforce this, and the SR-2 test covers a non-nominated holder of a valid ID.
  4. **Aggregate `count`.** It is still not added and is pending human decision **H-2**. Aggregates record presence (≥ 1) per interval only.
- 2026-09-29 — **H-2 decided (D-012); supersedes item 4 above.**
  - `AGGREGATE` records carry `count`, a non-negative integer: the number of occurrences of that outcome on that instance in the interval. It saturates at 2^53 − 1.
  - Only records with `count` ≥ 1 are written.
  - `count` is permitted only on `AGGREGATE` records, which are used exclusively for pre-principal failures. `AuditSink` rejects `count` on any other class.
  - Also: the Audit Project IAM statement in ARCHITECTURE is aligned to the SR-8 cross-project rule (D-013 follow-up). Workload- and gateway-project principals may hold only the conditioned workload `objects.create` and the read-only audit-reader role there.