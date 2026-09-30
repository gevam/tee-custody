# Decisions — tee-custody

Append-only log of every gate-routing decision, discussion outcome, refactor-vs-workaround call, human escalation, and assumption made while the human was unavailable. Format: templates/DECISION_RECORD.md. Never edit a past record; add a new one that supersedes it.

<!-- Records follow, newest last -->

## D-001 — Approve PROJECT.md increment baseline for G1 (INC-1, 2026-09-29)

Type: gate-routing
Chair / decider: Human
Participants: Orchestrator

**Options considered**
1. Approve PROJECT.md INC-1 through INC-5 as the baseline and reconcile framework.yaml later.
2. Hold G1 until framework.yaml contains a matching increments section.

**Decision:** Option 1.

**Reasoning:** The human explicitly approved the sequence in PROJECT.md as the baseline. The missing framework.yaml mapping is a configuration follow-up and does not leave the product scope unresolved.

**Dissent:** none

**Revisit when:** A material conflict between the project-defined sequence and architecture requirements is discovered.

**Follow-ups:** Architect to produce docs/INCREMENTS.md from the approved baseline; reconcile the framework.yaml mapping before work breakdown.

## D-002 — Route and close G2 contract findings (Project, 2026-09-29)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Architect

**Options considered**
1. Return the architecture to the Architect for missing/mismatched contracts, then re-check G2.
2. Pass G2 with the bundle transport, CLI, and platform capability contracts unresolved.

**Decision:** Option 1; after the Architect's corrections and re-check, G2 passes.

**Reasoning:** Initial review found missing bundle publication/retrieval, a simulator CLI mismatch (`--output-dir` instead of `--out`), and absent exact Core capability contracts for Transport, ShareVault, Fetcher, and Crypto. The Architect corrected these in `docs/ARCHITECTURE.md`. Re-check confirmed the required routes, CLI flag, all FR/NFR trace entries, capability signatures/error semantics, production adapter mapping, and INC-1 vertical path.

**Dissent:** none

**Revisit when:** A normative security or wire detail conflicts with the architecture during G3 or implementation.

**Follow-ups:** Before G4, reconcile the framework increment mapping; task contracts must copy exact normative claims, CDDL, `proto`, and cryptographic parameters.

## D-003 — Keep the reference gateway an untrusted relay (Project, 2026-09-29)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
1. Keep the reference gateway unauthenticated and untrusted; rely on cryptographic client/workload authentication, opaque ciphertext, and bounded abuse controls.
2. Add host-provided caller authentication and route authorization to the reference gateway.

**Decision:** Option 1.

**Reasoning:** The human chose to preserve the PROJECT.md boundary: host application authentication is out of scope and the gateway is a ciphertext relay. Route IDs are not identity proof; clients and the workload continue independent protocol authentication. This does not accept unrelated denial-of-service or metadata risks.

**Dissent:** none

**Revisit when:** A concrete host integration requires gateway authentication or new evidence shows the untrusted relay violates a normative security invariant.

**Follow-ups:** Security Architect to align T-01/SR-1 and assess residual risk; Architect must not add gateway auth without a new human decision.

## D-004 — Approve the G3 traceability-row edit (Project, 2026-09-29)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Architect

**Options considered**
1. Permit only the §13.8 row in `docs/security/traceability.md` to be updated to reference the G3-reviewed `docs/THREAT_MODEL.md`; leave every other row unchanged.
2. Leave the matrix untouched, keeping its G3 GAP and blocking G3.

**Decision:** Option 1.

**Reasoning:** The human approved this exact limited edit. No normative security requirement, invariant mapping, or other matrix row is authorized to change under this decision.

**Dissent:** none

**Revisit when:** Any additional change under `docs/security/` is proposed.

**Follow-ups:** Architect may update only the §13.8 row after the threat model is approved; all other traceability edits require separate human approval.

## D-005 — Return security findings to Architect (Project, 2026-09-29)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Security Architect, Architect

**Options considered**
1. Return the design findings to the Architect, then request Security Architect re-review.
2. Pass G3 with unresolved Critical/High design findings.

**Decision:** Option 1; G3 remains open.

**Reasoning:** The Security Architect returned CHANGES_REQUIRED. T-03, T-05, T-07, T-08, T-10, T-11, T-13, and T-14 remain design findings (one Critical, four High, three Medium). The human selected the untrusted gateway boundary in D-003; T-01 is a Medium residual risk pending explicit acceptance, not a design change. T-15 is also a Medium residual risk pending human acceptance.

**Dissent:** none

**Revisit when:** The Architect returns the required design updates and Security Architect completes re-review.

**Follow-ups:** Architect to address T-03/T-14 validation, T-05 audit, T-07 resource controls, T-08 tenant authorization, T-10 transport protection, T-11 secret/configuration lifecycle, and T-13 release signer governance; do not add gateway authentication or edit `docs/security/`.

## D-006 — Route G3 re-review findings to Architect (Project, 2026-09-29)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Security Architect, Architect

**Options considered**
1. Return F-1(b–e), F-2..F-5 to the Architect; put the T-05 attribution-field question (H-1) to the human in parallel.
2. Pass G3 with T-13 (Critical) and T-19 (High) design gaps open.

**Decision:** Option 1; G3 remains open.

**Reasoning:** Security Architect re-review 1 closed T-03, T-07, T-08, T-10, T-11, T-14 by design (tests required). Remaining: F-2 Critical (T-13: signers must rebuild independently outside CI before signing, spec §12), F-3 High (T-19: §10.3 web code-delivery mitigations absent), F-1 Medium (T-05 audit: platform audit path for operators per spec lines 201/302 — ADR 0005's rejection of platform audit logging contradicts the spec; release sign-offs to protected sink; audit bucket isolation; aggregated pre-auth failures; attribution fields pending H-1), F-4 Medium (T-20: §12 alerting MUST has no path), F-5 Medium (T-18: owner notification on recover_start, bounded pending recoveries). Orchestrator verified the cited spec lines. Operator attribution via platform audit logs needs no human decision: it is already normative.

**Dissent:** none

**Revisit when:** Architect returns; Security Architect re-review 2.

**Follow-ups:** H-1 to human (audit identifier fields). Residual-risk acceptance (T-01, T-15, T-17, T-19) batched to the human once the design is final.

## D-007 — H-1: audit identifier fields are within spec §11 (Project, 2026-09-29)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
1. Treat §11 as listing permitted identifier kinds; add `actor_client_id`, `subject_client_id`, `recovery_id` to the audit allow-list as an interpretation.
2. Treat §11 as a closed list and approve the three fields as a constraint-deviation for audit records only.
3. Reject; trustee attribution becomes a Medium residual risk.

**Decision:** Option 1.

**Reasoning:** Human decision. §11 permits identifiers of the listed kinds and forbids only payloads, keys, shares, nonces and ciphertext; trustees are clients, and owner↔trustee pairs already exist in TrusteeStore and AAD. `recovery_id` must never function as a bearer token or authorization input. `framework.yaml → coding_standards.logging` updated accordingly. Not a constraint-deviation; no change under `docs/security/`.

**Dissent:** none

**Revisit when:** A proposed field is not an identifier of a §11 kind (e.g. SR-6 aggregate `count`, which is batched to the human separately).

**Follow-ups:** Architect fills the F-1(a) placeholder.

## D-008 — Reserve the recovery cancel operation (Project, 2026-09-29)

Type: scope
Chair / decider: Orchestrator
Participants: Architect

**Options considered**
1. Add the owner's recovery-cancel operation to the reserved built-in operation names.
2. Leave PROJECT.md §4.1's reserved list as written.

**Decision:** Option 1.

**Reasoning:** Spec §8.3 step 4 requires owner cancellation; PROJECT.md §4.1 `recovery` module and §6 INC-4 and FR-12 already include cancel. The reserved-name list omission is an inconsistency, not a scope boundary; the normative spec controls. No scope growth.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Architect names the operation (e.g. `recover_cancel`) in the reserved list and contracts.

## D-009 — Increment mapping lives in docs/INCREMENTS.md (Project, 2026-09-29)

Type: gate-routing
Chair / decider: Orchestrator
Participants: —

**Options considered**
1. Treat `docs/INCREMENTS.md` (derived from the D-001 baseline) as the sole increment source; add no `increments` key to framework.yaml.
2. Add an `increments` section to framework.yaml mirroring INCREMENTS.md.

**Decision:** Option 1.

**Reasoning:** The framework schema (sdlc/templates/framework.yaml, PROCESS.md, role prompts) defines no `increments` key and no role reads one; PROCESS.md §3.2 makes INCREMENTS.md the artifact. A duplicate would drift. PROJECT.md §6's reference to `framework.yaml → increments` is stale wording, not a requirement. Closes the G1 "Framework mapping" blocker.

**Dissent:** none

**Revisit when:** The framework adds an increments key.

**Follow-ups:** Human may reword PROJECT.md §6 at their convenience (non-blocking).

## D-010 — Accept G3 residual risks (Project, 2026-09-29)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
1. Accept T-19 (High), T-13, T-01, T-15, T-17 (Medium), T-05, T-20 (Low) as documented in THREAT_MODEL.md re-review 2.
2. Accept all but T-19, reopening v1 scope toward mobile-first.

**Decision:** Option 1.

**Reasoning:** Human decision. T-19 is the spec §10.3 web-platform limit; the design carries every §10.3 mitigation. The README must state the limit and name mobile as the high-assurance path.

**Dissent:** none

**Revisit when:** @teecustody/mobile is scoped, or evidence that any listed control is ineffective.

**Follow-ups:** Security Architect records acceptance in THREAT_MODEL.md; INC-5 README states the T-19 limit.

## D-011 — T-21: host admission hook over recover_start trigger_evidence (INC-4, 2026-09-29)

Type: scope
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
1. Optional host admission hook evaluates `trigger_evidence` (spec §8.3 step 1) before a `recover_start` counts toward the per-owner bound.
2. Accept T-21 as residual.

**Decision:** Option 1, delivered in INC-4.

**Reasoning:** Human decision. Uses a field the spec already defines; small, no wire change anticipated; keeps a device-less owner able to recover.

**Dissent:** none

**Revisit when:** The hook requires a wire or normative change (→ human).

**Follow-ups:** Architect designs the hook contract; Security Architect confirms T-21 status.

## D-012 — H-2: permit `count` on aggregate audit records (Project, 2026-09-29)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
1. Permit a non-negative integer `count` on aggregate pre-authentication failure audit records only.
2. No count.

**Decision:** Option 1.

**Reasoning:** Human decision. Security Architect: no confidentiality impact; aids triage. framework.yaml logging allow-list updated.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Architect replaces the "at least one failure" fallback.

## D-013 — G3 passed (Project, 2026-09-29)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Security Architect

**Options considered**
1. Pass G3.
2. Hold G3.

**Decision:** Option 1.

**Reasoning:** Verified: THREAT_MODEL.md exists, Status APPROVE (re-review 2), zero threats with status `finding`; every High/Critical threat has a design mitigation; SR-1..SR-13 are in REQUIREMENTS.md, each with a test description; the human accepted the residual risks (D-010). Remaining items are non-blocking follow-ups: one ARCHITECTURE.md sentence contradicting the SR-8 audit-project IAM rule; T-21 hook design (D-011); `count` (D-012); §13.8 traceability row (D-004).

**Dissent:** none

**Revisit when:** Any change under docs/security/ or a new High/Critical threat.

**Follow-ups:** Architect and Security Architect clerical follow-ups before G4.

## D-014 — Standing authority for traceability coverage columns (Project, 2026-09-30)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator

**Options considered**
1. Architect may edit only the Coverage type / Location / Status columns of `docs/security/traceability.md`, pointing at real tests or review-checklist items; everything else under docs/security/ stays human.
2. Human approves matrix changes per increment.

**Decision:** Option 1.

**Reasoning:** Human decision. Avoids a per-increment stop for bookkeeping; requirement rows, doc version and all other docs/security/ files remain always-human. Security Reviewer verifies each such change at G7.

**Dissent:** none

**Revisit when:** Any matrix edit touches a requirement row or doc version.

**Follow-ups:** —

## D-015 — Configured test/coverage commands include tests/ and teecustody_sim (INC-1, 2026-09-30)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead

**Options considered**
1. Apply Tech Lead R-4: `test_command` adds `tests`; `coverage_command` adds `--cov=teecustody_sim` and `packages/teecustody-sim`.
2. Leave commands; contract and acceptance tests invisible to the configured suite.

**Decision:** Option 1; framework.yaml updated.

**Reasoning:** G4/G5/G6 checks run the configured commands; contract and acceptance tests must be in them, and teecustody-sim is a security path requiring 100% coverage. Commands remain single-line and clean-checkout runnable. Mechanical, reversible; no scope change.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** —

## D-016 — constraint-deviation: spec §6.8 image-signature check via Google-verified key_ids (INC-1, 2026-09-30)

Type: constraint-deviation
Chair / decider: Human
Participants: Orchestrator, Architect, Software Engineer (V-01)

**Requirement:** Spec §6.8 — `submods.container.image_signatures` contains valid signatures from at least `SIGNERS_REQUIRED` of the signer public keys embedded in the client; the client enforces this independently.

**Conflict:** V-01 (FACTS.md F-12, 2026-09-30, docs.cloud.google.com token-claims reference; go-tpm-tools@5d91b303) — the token carries `key_id`, `signature`, `signature_algorithm` per entry, but not the signed Simple Signing payload (an opaque registry blob the launcher forwards to the attestation service). The client cannot re-verify signature bytes from the token.

**Options considered**
1. Client requires ≥ `SIGNERS_REQUIRED` distinct `key_id`s in the Google-signed token equal to SHA-256(SPKI DER) fingerprints of embedded signer keys, with `signature_algorithm` in the allowed set (the check Google's documented WIP policy uses).
2. Operator ships payloads with the bundle; client re-verifies signatures and payload digest (spec/wire change).
3. Digest allow-list only; no client signature check.

**Decision:** Option 1.

**Security impact:** Signature validity is attested by Google's attestation service, which already underwrites every other token claim the client relies on; no new trusted party. The operator/server still cannot satisfy the check without the signers' keys. The client still enforces the signer set and threshold itself ("server enforces it" is not relied on). Residual: a compromised Google verifier could list unverified key_ids — but it could equally forge `image_digest`, so the attack surface is unchanged.

**Dissent:** none

**Revisit when:** Google documents the payload in the token or a verifiable payload retrieval path, or the threat model adds a Google-verifier-compromise threat.

**Follow-ups:** Architect finalizes option 1 in ARCHITECTURE/API (drop option-2-only fields); Security Architect assesses and records in THREAT_MODEL.md; traceability §6.8 row notes D-016 when its test lands (D-014 authority covers Location/Status only).

## D-017 — INC-1 contract rulings and V-01 routing (INC-1, 2026-09-30)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Architect, Tech Lead, Security Architect

**Options considered**
1. Accept the Architect's CI-1..CI-10 rulings; send ADR 0009 (project-owned RS256 JWS handling over audited RSA primitives) and ADR 0010 (project-owned TS canonical CBOR codec, replacing cbor-x, retiring V-2.1) to Security Architect for sign-off; then Tech Lead amends contracts for the rulings, D-016, and V-01 rows F-03/F-05/F-09/F-11/F-15 using conservative defaults.
2. Re-open rulings.

**Decision:** Option 1.

**Reasoning:** Rulings resolve every Wave-0 type gap. ADR 0010 replaces an approved crypto-list dependency and ADR 0009 is security-critical parsing: dependency_policy requires ADR + Security Architect sign-off before Wave 0. V-01 non-F-12 rows are resolvable by the Tech Lead without spec change: accept both nonce encodings; nonce length within the intersection of documented ranges; production hwmodel allow-list from documented confidential values (no GCP_SHIELDED_VM); reject `swname`≠CONFIDENTIAL_SPACE and unexpected support attributes.

**Dissent:** none

**Revisit when:** Security Architect rejects either ADR.

**Follow-ups:** G4 re-check after Tech Lead amendment.
