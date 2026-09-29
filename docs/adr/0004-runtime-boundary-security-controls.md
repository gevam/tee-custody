# ADR 0004: Runtime Boundary Security Controls

## Status

Proposed; amended 2026-09-29 (D-006, finding F-5). T-05 is handled in ADR 0005 and its amendment.

## Context

The threat review found incomplete validation, abuse limits, tenant authorization, and production transport requirements at trust boundaries. The project already has typed ports, a Reference Gateway, production adapters, platform workload identity, and the configured GCP services. D-003 requires the gateway to remain an unauthenticated ciphertext relay and route IDs to remain non-authoritative. Host application authorization remains host-owned.

## Decision

Apply strict typed/schema validation, canonical wire checks, and finite configured bounds at every less-trusted boundary before domain work, mutation, or expensive operations. Each boundary owner validates input and adapter output; there is no fallback parser. Operational limits are required finite configuration, with normative maxima controlling wire limits.

Apply finite per-source and global gateway limits without caller authentication, bounded queue batches/polls/retries, and per-authenticated-principal plus global budgets for expensive workload operations. Over-budget work fails before mutation and does not silently drop custody transitions.

Use a workload authorization policy for authenticated-principal, library operation, tenant owner, epoch, and recovery-state checks before dispatch/backend access. Adapters scope access to authorized tenant identifiers as defense in depth. The library does not claim host-account or host-application authorization; those decisions remain with host handlers. No gateway auth or route-ID authority is introduced.

All networked production adapters require authenticated TLS, platform service-identity validation, no downgrade, and no untrusted redirects. Simulator endpoints remain development-only. These controls use existing components and dependencies.

## Consequences

Production configuration fails startup if mandatory operational bounds or secure endpoints are absent or invalid. Boundary tests must cover malformed and oversized data, limit exhaustion, cross-tenant attempts, and transport identity/redirect failures. Numeric deployment limits must be selected and recorded before release; this ADR does not invent values or change the normative wire limits. T-03, T-07, T-08, T-10, and T-14 are addressed by design, subject to security review and tests. T-05 is not closed by this ADR.

## Alternatives considered

- Authenticate callers at the gateway or trust route IDs: rejected by D-003 and the approved trust model.
- Leave checks to individual handlers/adapters without a common policy: rejected because it permits inconsistent tenant and parser behavior.
- Add a rate-limit or policy cloud service: rejected because existing gateway/workload boundaries can enforce the controls without adding infrastructure.
- Permit plaintext or redirecting production transports: rejected because service identity and confidentiality must hold at every network boundary.

## Amendments

- 2026-09-29 — **F-5 [Medium, T-18], D-006. Refactor of the FR-12 contract.** Spec §8.3 step 1 only requires notifying trustees. But spec §8.3 step 4 (cancel "by the owner's existing client at any time") is useless if the owner never learns a recovery started, and `recover_start` has no authenticated principal (the new device has no `cs`). Decisions (details in ARCHITECTURE "Recovery start, notification and authorization"):
  1. **Subject, not principal.** `owner_id` in `recover_start` is a subject only, never a principal.
  2. **Notify owner first.** `Notifier.notify(owner_id, RECOVERY_PENDING)` precedes the trustee notifications. The start is acknowledged only after all notifications are accepted. Otherwise the recovery becomes `CANCELLED` (fail closed).
  3. **Per-owner bounds.** `TrusteeStore.create_pending_recovery` atomically enforces `MAX_PENDING_RECOVERIES_PER_OWNER` and `RECOVERY_STARTS_PER_OWNER` per `RECOVERY_START_WINDOW` (`BoundaryLimits`; project defaults 2 and 4 per 24 h). It returns the new dispatch category `LIMIT_EXCEEDED` with no state change.
  4. **`recovery_id` grants nothing.** Release requires an authenticated nominated trustee. Completion requires the `RIB_priv` matching the recorded `RIB_pub`. Cancel requires the authenticated owner principal.
  5. **Notifier contract.** `notify(owner_id, event)` becomes `notify(recipient, event)` with `RECOVERY_PENDING`, `RECOVERY_REVIEW_REQUESTED` and `SHARE_REJECTED`.
  - Consequences:
    - A per-owner bound lets an attacker who knows an `owner_id` occupy that owner's pending slots until `RECOVERY_TTL`. If the owner has lost their only device, they cannot cancel. That is availability, a spec §2 non-goal. A bound > 1 limits the effect, and trustees see every pending request with its `started_at`.
    - The cancel operation's reserved name is missing from PROJECT.md §4.1 and must come from `spec/wire` (human-controlled).
- 2026-09-29 — **D-008.** The owner's cancel operation is named `recover_cancel` and added to the reserved built-in names. It is authorized only for the authenticated owner principal of a `PENDING` recovery. An unknown ID and an unauthorized request return the same `NOT_AUTHORIZED`. It is idempotent on an already-cancelled recovery. Its CDDL payload (logical input: `recovery_id`) is authored in `spec/wire` under the human-controlled process.
- 2026-09-29 — **D-011 (T-21).** Adds an optional host recovery-admission hook, `Workload.recovery_admission`, with signature `(RecoveryAdmissionRequest{owner_id, trigger_evidence, received_at}) -> ADMIT | REJECT`.
  - **Placement.** It runs after Directory resolution and the global recovery budget, and before `create_pending_recovery`.
  - **Outcomes.** `REJECT` returns `NOT_AUTHORIZED`. An exception, timeout or invalid return value fails closed as `BACKEND_UNAVAILABLE`. Neither mutates state, sends notifications, or counts toward the per-owner bounds; both are recorded as counted aggregates.
  - **Default.** With no hook registered, every request is admitted (T-21 as accepted in D-010).
  - **Bounds.** Only admitted requests can receive `LIMIT_EXCEEDED`. The bounds stay in force behind the hook.
  - **Constraints.** No wire change: `trigger_evidence` is already in spec §8.3 step 1. Because of the spec §11 egress limit, evidence must be self-verifiable inside the TEE. Details are in ARCHITECTURE "Host recovery-admission hook".