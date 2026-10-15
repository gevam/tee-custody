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

## D-018 — G4 applied per wave; INC-1 Wave 0 passes (INC-1, 2026-09-30)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead

**Options considered**
1. Apply G4 per wave: Wave 0 (tooling, API stubs, wire binding, facts) starts on contract-test stubs; no Wave 1+ task starts until QA acceptance tests covering it exist on trunk and fail for the right reason on post-Wave-0 trunk. V-01 branch merges with Wave 0.
2. Require QA acceptance tests before Wave 0.

**Decision:** Option 1; G4 passes for Wave 0.

**Reasoning:** PROCESS.md §3.6 schedules QA authoring after Wave 0, and acceptance tests cannot import an API that Wave 0 creates; Wave 0 tasks deliver tooling and frozen stubs, whose acceptance evidence is the contract tests. Orchestrator verified: no same-wave file overlap (T-06/T-07/T-08 basename matches are in different packages; pytest importlib mode set in T-01); all dependencies point to earlier waves; contract stubs exist for every INC-1 boundary (tests/integration/contracts: launcher, sim OIDC, sim CLI, wire, trust-profile, verifier, vectors); Wave 0 is 4 items = max_engineers.

**Dissent:** none

**Revisit when:** A Wave 1 task is proposed to start without failing acceptance tests.

**Follow-ups:** QA authors INC-1 acceptance tests once Wave 0 merges; G4 re-checked for Wave 1. Open non-blocking: F-16 verification (V-01 re-run); SR-1 test (i) wording (profiles carry no SPKI) → Security Architect; support_attributes override (Architect, only if a host needs it).

## D-019 — SR-9 release-age rule scoped to shipped and build dependencies (Project, 2026-10-01)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Reviewer

**Options considered**
1. Apply the 18-month rule to runtime deps, build backends and anything in shipped artifacts; exempt dev/test tooling and its transitive deps from the age rule only (still OSI licence, exact lock, audit scanners).
2. Keep the rule universal with named exceptions (sortedcontainers 2.4.0, colorama 0.4.6).
3. Enforce strictly (drop hypothesis).

**Decision:** Option 1; framework.yaml dependency_policy updated.

**Reasoning:** Human decision. Raised by the T-01 security review (N1): two transitive dev-only packages exceed the age rule; neither ships; pip-audit clean.

**Dissent:** none

**Revisit when:** A dev tool is found to influence shipped artifacts (e.g. codegen), which would put it under the rule.

**Follow-ups:** Security Architect aligns SR-9 wording in REQUIREMENTS.md at next touch. T-01 security Lows: import-ban bypasses (dynamic import, noqa, other listener APIs) → Tech Lead folds a semgrep rule into a Wave-1 tooling task; unlocked build backend (hatchling) → INC-5 reproducible-build scope.

## D-020 — Human approves T-03 spec/wire and spec/vectors content (INC-1, 2026-10-01)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Code Reviewer, Security Reviewer, Tech Lead

**Options considered**
1. Approve T-03 (canonical CBOR rules incl. rule-5 classifications, `proto` = "tee-chan-v1", attestation-vectors CDDL, 114 codec vectors, harnesses) for merge.
2. Request changes.

**Decision:** Option 1.

**Reasoning:** Human decision (framework.yaml always_human: spec/wire, spec/vectors). Both reviewers APPROVE in round 2; independent codecs from both reviewers and the engineer pass every vector. T-18's generated suite/corpus files require separate human approval.

**Dissent:** none

**Revisit when:** Any later change to spec/wire or spec/vectors.

**Follow-ups:** Release Engineer merges T-03, V-01, QA acceptance tests. Tech Lead adds `5b0000000100000000` → MALFORMED as a T-09 unit criterion (32-bit length truncation; security re-review Low) — not a spec/vectors change.

## D-021 — G4 passes for INC-1 Wave 1 (INC-1, 2026-10-01)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead, QA Engineer

**Options considered**
1. Pass G4 for Wave 1 and start batch B1 (T-04, T-07, T-09, T-10).
2. Hold.

**Decision:** Option 1.

**Reasoning:** Verified on main (04b5267): Wave 0 fully merged (T-01 e22c759, T-02 815f379, T-03 c9d0e95 after D-020, V-01 92538a0, QA 05ce1de). Wave-1 owned-file sets are pairwise disjoint (46 files; two same basenames are in different packages). All Wave-1 inputs exist. Acceptance tests exist and none passes on trunk (9 Python + 2 TS passes are harness/contract self-checks, not acceptance). Contract stubs exist and fail per WAVES.md expected-red table. DEBT: 0 open.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Retro: Release Engineer stashed an unrelated uncommitted edit (T-09.md) despite an explicit "never stash" instruction; restored by the Orchestrator (04b5267). Retro: eslint.config.js committed before its test (T-02, accepted as tooling).

## D-022 — Duplicate-encoding signer keys handled at profile generation, not in the client (INC-1, 2026-10-01)

Type: refactor-vs-workaround
Chair / decider: Orchestrator
Participants: Security Reviewer, Tech Lead

**Options considered**
1. Reject non-canonical and duplicate signer keys where profiles are generated (T-17 dev generator now; INC-5 production `teecustody-profile` tool), leaving the client's §6.8 count over distinct profile key_ids (D-016) unchanged.
2. Route to Architect to give Core key material and async crypto in `checkImage` so it can deduplicate by key.

**Decision:** Option 1.

**Reasoning:** Under D-016 the profile carries key_id fingerprints only; inflating the threshold requires a profile that lists one key under two encodings. Profiles are produced only by the generator/tooling and every signer-set change is human-approved (always_human). Guarding the single producer is a structural control; option 2 changes a frozen Wave-0 API mid-wave for a threat already gated by human approval.

**Dissent:** none

**Revisit when:** Profiles can be produced other than through the project tooling.

**Follow-ups:** T-17 criterion 2a (`NONCANONICAL_SIGNER_SPKI`, `DUPLICATE_SIGNER_KEY`) — Tech Lead amendment. Architect: add the same rejection as an acceptance criterion of the INC-5 production profile tool in INCREMENTS.md at next touch (BACKLOG B-05 until then).

## D-023 — Raise parallelism.max_engineers from 4 to 8 (INC-1, 2026-10-01)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator

**Options considered**
1. Raise to 8. 2. Raise to 6. 3. Keep 4.

**Decision:** Option 1; framework.yaml updated.

**Reasoning:** Human decision. Four independent review-fix rounds (T-07, T-11, T-12, T-09) plus T-05/T-14 were queued behind the cap; each is its own branch with disjoint file ownership. Budget is unlimited.

**Dissent:** none

**Revisit when:** Token spend becomes a constraint, or concurrent merges cause conflicts.

**Follow-ups:** —

## D-024 — T-05 third review round, scoped (INC-1, 2026-10-01)

Type: gate-routing
Chair / decider: Tech Lead (escalation at review.max_rounds)
Participants: Code Reviewer, Security Reviewer, Orchestrator

**Options considered**
1. Authorise one round 3 limited to the propagate=False test (basicConfig before import, SENTINEL absent) plus re-check of e625149 by both reviewers.
2. Other resolution.

**Decision:** Option 1.

**Reasoning:** Single Medium test gap with a known, local fix; implementation already correct. Further changes are not permitted in round 3.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Retro: review rounds frequently find test-gap Mediums (mutation survivors); consider requiring engineers to run their own revert checks per criterion before reporting DONE.

## D-025 — Add T-20 for §G missing-claim vector rows; frozen-file exception for cases.py (INC-1, 2026-10-01)

Type: scope
Chair / decider: Orchestrator
Participants: Tech Lead, Security Reviewer

**Options considered**
1. Add task T-20 (Wave 2, before T-18) owning the changes needed for §G rows 29–37 (eight single-check missing-claim cases + `kid_unknown`), with a one-time exception allowing T-20 to modify the Wave-0 final file `cases.py` (NEGATIVE_CASES).
2. Defer the rows to INC-2.

**Decision:** Option 1.

**Reasoning:** Spec §13.2 requires negative tests per check and §15.3 requires the simulator to emit any single claim removed; vectors are the cross-implementation oracle, so missing-claim behaviour must be pinned in both languages before T-18 commits the suite. Effort growth: INC-1 18 → 20 tasks (T-19, T-20) ≈ 11%, below escalation.effort_growth_pct (30%). Exception is limited to adding catalog rows; no signature or type change to frozen files.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Tech Lead writes T-20.md; T-18 depends on T-20. Retro: catalog completeness should be reviewed at G4.

## D-026 — Human approves T-20 spec/vectors change (INC-1, 2026-10-01)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Code Reviewer, Security Reviewer

**Options considered**
1. Approve the nine appended CatalogRows in spec/vectors/test_attestation_suite.py (§G rows 29–37).
2. Request changes.

**Decision:** Option 1.

**Reasoning:** Human decision (always_human: spec/vectors). Both reviewers APPROVE; reviewers independently ran all 36 cases through main's verifyAttestation with the expected check/code.

**Dissent:** none

**Revisit when:** T-18 generated vector files (separate human approval).

**Follow-ups:** Merge T-20. Retro: a shared-scratchpad script clash briefly mutated an inactive worktree (T-15) during T-17 work — restored clean; engineers must use task-specific scratch subdirectories.

## D-027 — Re-apply T-20 after a mistaken revert (INC-1, 2026-10-01)

Type: gate-routing
Chair / decider: Human (authorised the Orchestrator to run the command)
Participants: Orchestrator, Release Engineer

**Options considered**
1. Orchestrator runs `git revert --no-edit 3f34b8b` (new commit, no history rewrite) after verifying every required merge command passed at the T-20 merge 59e98f6.
2. Human runs it. 3. Leave T-20 reverted.

**Decision:** Option 1 — applied as aeb6232; Python 1105 passed, ruff/format/mypy/TS lint/typecheck clean.

**Reasoning:** The Release Engineer reverted T-20 citing failures that were expected-red tests (spec/vectors, contracts, acceptance awaiting T-16/T-17/T-18). The agent's own re-revert was blocked by the permission system; the human chose to authorise the Orchestrator.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Release Engineer prompts now list the exact REQUIRED commands and the EXPECTED-RED paths, and forbid reverting. Retro: FAST-tier Release Engineer misjudged expected-red tests; consider STRONG-tier Release Engineer or a scripted merge gate.

## D-028 — R-11 applied: semgrep in lint_command; Wave 1 complete (INC-1, 2026-10-01)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead

**Options considered**
1. Append `uvx semgrep==1.178.0 --config .semgrep.yml --error --metrics=off` to framework.yaml lint_command now that T-14 is merged.
2. Keep semgrep CI-only.

**Decision:** Option 1.

**Reasoning:** WAVES R-11; the semgrep layer is the structural fix for lint-ban bypasses (§6 recurring class). Verified: full lint_command exits 0 on main (17 rules, 0 findings). Single-line, clean-checkout runnable. All Wave 1 tasks (T-04..T-14) merged.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** —

## D-029 — T-19 scoped round 3; T-16 merged by Orchestrator with human authorisation (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Tech Lead (T-19 round limit); Human (T-16 merge execution)
Participants: Orchestrator, Code Reviewer, Security Reviewer, Release Engineer

**Options considered**
T-19: 1. Scoped round 3 — candidate dedupe + per-value budget (1,024 candidates, 1 MiB) failing closed, attack input < 2 s, pin two escaped-name cases, fix slow-drip flake (accept ConnectionResetError) as criterion 6; T-19.md amended to record one-pass JSON-escape decoding. 2. Other.
T-16: the Release Engineer's `git merge --no-ff` was blocked by the permission system; human chose to have the Orchestrator merge.

**Decision:** T-19 Option 1. T-16 merged by the Orchestrator (dcd6e0b; 1406 Py / 877 TS green; lint_command incl. semgrep exit 0).

**Reasoning:** Security Medium (exponential decode cost hangs Simulator.start()) is in scope of T-19's own detector; the flake lives in a T-19-owned file.

**Dissent:** none

**Revisit when:** A later Release Engineer merge is blocked — ask the human again (per their instruction).

**Follow-ups:** Retro: the permission classifier intermittently blocks Release Engineer merges; consider a project permission rule for `git merge --no-ff inc-1/*` (human decision).

## D-030 — Human approves T-18 generated vectors (INC-1, 2026-10-05)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Code Reviewer, Security Reviewer

**Options considered**
1. Approve spec/vectors/attestation/suite.cbor (37 cases) and spec/vectors/wire/differential-corpus.json (512 cases, seed 1) for commit.
2. Request changes.

**Decision:** Option 1.

**Reasoning:** Human decision (always_human: spec/vectors). Both reviewers APPROVE: canonical CBOR per approved CDDL, §G rows 1–37 exact, each negative fails its single declared check (debug_bad_signature two by design), §13.9 holds, development anchors only, no private material, corpus byte-identical on regeneration; Python 212 and TS contract suites pass. Orchestrator verified independently.

**Dissent:** none

**Revisit when:** Any regeneration of spec/vectors.

**Follow-ups:** Merge T-18.

## D-031 — G6 Low defects: fix all within INC-1 (INC-1, 2026-10-05)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, QA Engineer

**Options considered**
1. Defer D-01..D-04 and the vectors-overwrite guard to INC-2.
2. Fix the overwrite guard now, defer the rest.
3. Fix all now, in a small INC-1 fix wave before G7.

**Decision:** Option 3.

**Reasoning:** Human decision. QA Phase 2: all INC-1 requirements pass; 0 Critical/High/Medium; 4 Low (D-01 CLI maps OS failures to INTERNAL; D-02 dev profile accepts non-canonical loopback `0x7f.1`; D-03 launcher drops connections under a 100-connection burst; D-04 `serve --env "=x"` accepted) plus an unguarded `vectors --out` overwrite of human-approved spec/vectors (QA near-miss; verified intact).

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Tech Lead writes Wave-4 fix contracts; G4/G5/G6/G7 re-checked for the fix wave; then G8.

## D-032 — Wave-4 enablers: config.py exception; README pre-approval (INC-1, 2026-10-05)

Type: scope
Chair / decider: Orchestrator (config.py exception); Human (spec/vectors/README.md line)
Participants: Tech Lead

**Options considered**
1. Grant T-21 a one-time Wave-0 frozen-file exception for packages/teecustody-sim config.py to add the `BIND_FAILED` error code only (no signature/type change); human pre-approves T-23's single README line under spec/vectors.
2. Route D-01 through existing codes only / defer.

**Decision:** Option 1.

**Reasoning:** D-031 requires D-01 fixed now; a specific bind-failure code is the minimal interface addition (pattern of D-025). Human pre-approved the README change `teecustody-sim vectors --out spec/vectors/` → `... --force` on the condition the merged diff is exactly that one line (Orchestrator verifies at merge; anything more returns to the human).

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Tech Lead applies API.md §C text (BIND_FAILED, OUTPUT_EXISTS, `vectors --force`). QA writes failing acceptance tests for D-01..D-04 + guard (G4 for Wave 4).

## D-033 — G4 passes for INC-1 Wave 4 (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead, QA Engineer

**Options considered**
1. Pass G4 for Wave 4 (T-21, T-23, T-24) and start engineers.
2. Hold.

**Decision:** Option 1.

**Reasoning:** Verified on main 86bfda4: owned-file sets of T-21/T-23/T-24 are disjoint; inputs exist (all INC-1 Waves 0–3 merged; API.md §C Wave-4 text 975c559; D-032 exceptions); acceptance tests tests/acceptance/test_WAVE4_sim_defects.py (9 failed, 1 error) and D02.profile-canonical.test.ts (8 failed) exist and fail on trunk for the intended reasons; required suites otherwise green.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** —

## D-034 — G5 passes for INC-1 (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Orchestrator
Participants: —

**Options considered**
1. Pass G5. 2. Hold.

**Decision:** Option 1.

**Reasoning:** Verified on main f052061 with framework.yaml commands: test_command exit 0 (Python 1806, core TS 901, tests package 323, spec/vectors 212); lint_command exit 0 (incl. semgrep); coverage_command exit 0 — Python teecustody + teecustody_sim 100% line and branch (2018 stmts, 458 branches), @teecustody/core 100% statements/branches/functions/lines. All INC-1 tasks (T-01..T-24, V-01) merged with Code + Security APPROVE. Approved spec/vectors files byte-identical to D-030.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** G6 confirmation by QA; G7 increment-level security pass.

## D-035 — G6 passes for INC-1 (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Orchestrator
Participants: QA Engineer

**Options considered**
1. Pass G6. 2. Hold.

**Decision:** Option 1.

**Reasoning:** QA re-ran on integrated main 94dd29a: Python acceptance 124/124, TS @teecustody/tests 323/323, spec/vectors + tests/integration 255/255. D-01..D-04 fixed in Wave 4 (T-21, T-23, T-24) and closed with verifying tests (D-031); no open defects at any severity. Every INC-1 acceptance criterion passes (docs/qa/INC-1.md, inc-1/qa-g6 bab6ed3).

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Merge inc-1/qa-g6 (docs only). G7 pending.

## D-036 — G7 passes for INC-1 (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Security Reviewer

**Options considered**
1. Pass G7. 2. Hold.

**Decision:** Option 1.

**Reasoning:** Every INC-1 branch had Code + Security APPROVE. Increment-level pass on main 94dd29a: APPROVE, no finding ≥ Medium. gitleaks full history clean; pip-audit/pnpm audit clean; bandit/semgrep Medium+ only false positives in fixtures/negative tests; dependency policy exit 0; trivy N/A. Spec, security README and all 33 matrix rows at 1.0; all 70 tests cited by covered/partial rows exist and fail when their control is broken; non-negotiables hold. §13.11 correctly GAP (CI workflow exists but has never run — no upstream). B-06, B-08, B-13 must be in INC-2 contracts.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** G8 (tag inc-1) on human decision; retrospective.

## D-037 — G8: INC-1 tagged locally (INC-1, 2026-10-05)

Type: gate-routing
Chair / decider: Human (tag scope); Orchestrator (gate)
Participants: —

**Options considered**
1. Tag `inc-1` locally only. 2. Tag and push to origin. 3. Hold.

**Decision:** Option 1 — annotated tag `inc-1` on 957ed82; not pushed.

**Reasoning:** G5 (D-034), G6 (D-035), G7 (D-036) passed; trunk green and deployable per ARCHITECTURE (simulator-first; no image in INC-1). Human chose no external side effect yet; CI has therefore never run on GitHub (§13.11 stays GAP).

**Dissent:** none

**Revisit when:** Human decides to push.

**Follow-ups:** Retrospective (3.9); INC-2 work breakdown must include BACKLOG B-06, B-08, B-13 (required) and B-05 tracked for INC-5.

## D-038 — Apply INC-1 retrospective recommendations 1–5; Release Engineer permission rule (Project, 2026-10-05)

Type: refactor-vs-workaround
Chair / decider: Human (accepted all five; approved the permission rule)
Participants: Retrospective Analyst, Orchestrator

**Options considered**
Accept any subset of docs/retro/INC-1.md recommendations 1–5; add or not a project permission rule for Release Engineer merges.

**Decision:** All five applied; permission rule added (.claude/settings.json: `git merge --no-ff inc-*`, `git rebase main`, and `git -C *` forms only).

**Reasoning:** (1) Mutation self-check in Task Report / software-engineer / code-reviewer — test-gap Mediums dominated review rounds. (2) Wave-0 stubs pin signatures only; Tech Lead names owners for frozen enum/catalogue rows. (3) Release Engineer runs REQUIRED/EXPECTED-RED lists only; no stash/reset/revert/clean/add -A; stop on permission blocks. (4) Architect gives concrete signatures, error enums and an example call per interface; PROCESS §3.2 G2 fails prose-only interfaces. (5) STATUS records spend and review rounds; PROCESS §3.4 G4 requires new scanner rules in lint_command and Required BACKLOG items carried into INCREMENTS.md. Edits made in sdlc/roles and mirrored in .claude/agents (sdlc/scripts/init-project.sh is absent, so agents cannot be regenerated).

**Dissent:** none

**Revisit when:** INC-2 retro — re-evaluate #4 (retro confidence note).

**Follow-ups:** INC-2 work breakdown must include BACKLOG B-06, B-08, B-13.

## D-039 — INC-2 pre-G4: additive changes to INC-1 final files; CI placement of browser tests (INC-2, 2026-10-05)

Type: scope
Chair / decider: Orchestrator
Participants: Architect

**Options considered**
1. Accept the five additive changes to INC-1 "final" files listed in docs/INC-2-API.md §13 (`IdentityKey.sign`, runtime brand registry in attestation/types.ts, new exports in index.ts and channel/__init__.py, third output file from `teecustody-sim vectors`) — additions only, no existing signature change — each to be owned by exactly one INC-2 task. 2. Require new modules instead.

**Decision:** Option 1. Q4 (browser tests in CI): the headless-browser (Playwright) suites run in the existing simulator CI test job with pinned browser builds and no credentials; framework.yaml test_command gains them only if they are deterministic and fast enough, otherwise a separate required CI job — Tech Lead to specify in INC-2 contracts.

**Reasoning:** Additive changes keep the INC-1 frozen API stable (existing signatures unchanged; Wave-0-stub rule from D-038 applies). No constraint-deviation involved. Q1/Q2 (proto, CDDL) and Q5 (security.paths) go to the human after Security Architect review; Q3 to the Security Architect.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Security Architect pre-G4 review of INC-2-API.md, ADR 0011 and CDDL; human batch (CDDL + proto, security.paths).

## D-040 — INC-2 pre-G4 security review: route R-1..R-8 to Architect (INC-2, 2026-10-05)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Security Architect, Architect

**Options considered**
1. Return R-1..R-8 to the Architect before the human sees the CDDL; keep R-8 (idle-session eviction before rejecting on a full session table) in INC-2. 2. Proceed with known gaps; defer R-8 to INC-3.

**Decision:** Option 1.

**Reasoning:** Security Architect: R-5 High (session nonce/seq never reused: assigned inside encrypt, never caller-supplied, never rolled back), R-1/R-4/R-7/R-8 Medium, R-2/R-3/R-6 Low. Several change the CDDL (R-1 timestamp cap 2^53−1, R-2/R-3 schema rules), so human approval waits for the revision. R-8 is SR-4 DoS protection and cheap inside INC-2's own session table. ADR 0011 Accepted with conditions C1–C7 (pyhpke on the workload per spec §11; pins+hashes amendment signed off before lock-file merge; RFC 9180 vectors incl. export, fail on empty filter). Q3: filter expired pre-keys individually, after all signatures verify. New residuals T-26..T-28 Low/informational (no human acceptance needed).

**Dissent:** none

**Revisit when:** Architect returns the revision; Security Architect re-check.

**Follow-ups:** Human batch: CDDL + proto, security.paths (Q5 recommendation from Security Architect).

## D-041 — Human: INC-2 wire format approved, proto kept, security.paths widened (INC-2, 2026-10-06)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Architect, Security Architect

**Options considered**
Q2 approve / change the INC-2 CDDL (docs/INC-2-API.md §3: channel.cddl, channel-vectors.cddl); Q1 keep / bump `proto`; Q5 add Security Architect's recommended paths to security.paths (all / all but gateway).

**Decision:** CDDL approved as specified (final spec/wire files still return to the human at merge); `proto = "tee-chan-v1"` kept (spec §5.3 verbatim); all recommended paths added to framework.yaml security.paths.

**Reasoning:** Human decisions after Security Architect APPROVE of the revised design (R-1..R-8 closed; R-6 clerical fix applied: purge when expires_at < now).

**Dissent:** none

**Revisit when:** Any later spec/wire change.

**Follow-ups:** Tech Lead INC-2 work breakdown (G4) from docs/INC-2-API.md, honouring D-038 rules.

## D-042 — G4 passes for INC-2 Wave 0 (INC-2, 2026-10-06)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead

**Options considered**
1. Pass G4 for Wave 0 (T-01..T-06, V-01, V-02); hold T-21/T-32 on CI-2-1. 2. Hold all.

**Decision:** Option 1.

**Reasoning:** Verified: Wave-0 owned files (53) pairwise disjoint; inputs exist (inc-1 on main; INC-2-API approved D-041; ADR 0011 Accepted w/ conditions); contract test stubs committed (c2bc2e0); acceptance tests for Wave 1+ authored by QA after Wave 0 merges (D-018 convention). CI-2-1 (browser cannot read Google discovery: no CORS on confidentialcomputing.googleapis.com; JWKS endpoint has CORS — verified by Orchestrator 2026-10-06) blocks only T-21 and T-32; Security Architect analysing options before a human decision.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** Apply framework.yaml command changes when T-01 merges (WAVES Orchestrator action 1).

## D-043 — Constraint-deviation: spec §6.1 JWKS location pinned in the trust profile (CI-2-1) (INC-2, 2026-10-11)

Type: constraint-deviation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Constraint:** docs/security/tee-security-architecture.md §6.1. At runtime the client fetches the discovery document over TLS from the exact issuer origin and takes `jwks_uri` from it.

**Options considered**
A. Pin the exact `jwks_uri` in the compiled trust profile for every client, with no runtime discovery fetch. The `teecustody-profile` build verifies the discovery binding at build time, and a scheduled real-GCP CI job re-checks it.
B. Relay discovery through the gateway, plus an exact-URI pin.
C. `TOKEN_TYPE=PKI`.

**Decision:** Option A, chosen by the human after the Security Architect recommended it (THREAT_MODEL review log, 2026-10-06).

**Reasoning:**
- Browsers cannot read Google's discovery document. It sends no `Access-Control-Allow-Origin`, while the JWKS endpoint does (verified 2026-10-06).
- A build-time pin closes T-29 (JWKS path substitution on the shared googleapis origin), which INC-1's origin-only check leaves open whenever discovery is not fetched directly from Google.
- Spec §10.2 already places the JWKS location in the compiled profile.
- B adds an untrusted ingress and is still a deviation. C needs X.509 path validation in the browser, which conflicts with ADR 0009.

**Scope of deviation:** the discovery step moves from client runtime to profile build time. One code path covers Node and browser (I13). Discovery is never relayed or proxied.

**Residual risk accepted:** T-29 post-deviation (Low). A Google JWKS URI or CORS change makes clients fail closed until a profile release; the scheduled binding check detects it.

**Dissent:** none

**Revisit when:** Google adds CORS to discovery, changes the JWKS URI, or the spec is revised.

**Follow-ups:**
- The Architect amends INC-2-API with design deltas (1)–(5) from the Security Architect's CI-2-1 entry.
- The Tech Lead amends or adds INC-2 tasks, including changes to INC-1 code in profile.ts/signature.ts, and unblocks T-21/T-32.
- The Security Architect re-checks the deltas and sets T-29 to mitigated by design.
- Trust profile and spec/vectors changes return to the human at merge (always_human).

## D-044 — T-06 satisfied on trunk (INC-2, 2026-10-11)

Type: gate-routing
Chair / decider: Orchestrator
Participants: —

**Options considered**
1. Merge inc-2/T-06-backlog through review. 2. Close T-06 as satisfied, because its rows are already on trunk.

**Decision:** Option 2.

**Reasoning:** Before the restart, B-24..B-27 also appeared as uncommitted lines in main's working tree, and they were committed with D-043 (4c823a3). The Orchestrator checked them: they are byte-identical to the verbatim rows in the T-06 contract. `git diff main inc-2/T-06-backlog -- docs/BACKLOG.md` is empty. The content is a verbatim FAST documentation spec with no code, so review adds nothing. The branch is retained, not merged. For the retro: an agent wrote outside its worktree. The likely cause is absolute paths into the main checkout.

**Dissent:** none

**Revisit when:** —

**Follow-ups:** The retro checks the worktree-isolation instructions in the engineer prompt.

## D-045 — Human: admit @hpke/core with @hpke/common under ADR 0011 C3a/C7a (H-HPKE) (INC-2, 2026-10-12)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Architect

**Options considered**
A. Admit @hpke/core 1.9.0 and @hpke/common 1.10.1, scoped by a `framework.yaml` `dependency_policy` exception and new ADR conditions C3a/C7a.
B. Pin the pre-vendoring @hpke/common 1.7.3.
C. Block HPKE in the browser until upstream fixes it.

**Decision:** A, chosen by the human. The Orchestrator applied the Security Architect's wording verbatim to `framework.yaml`: the `security.dependency_policy` exception, and the `forbidden_dependencies` pure-JS entry marked "except as admitted in security.dependency_policy".

**Reasoning:** V-01 found two problems:
- C7: an unresolved `import("crypto")` sits in a try/catch Node ≤18 fallback that runs only when `globalThis.crypto` is absent.
- C3: @hpke/common ≥1.8.0 vendors pure-JS noble X25519 and hash code. Our path never reaches it, but two dead fragments do reach the bundle.

Spec §10.2 is still met. The literal framework rule forbade the package, so admitting it was the human's call. B expires on 2026-12-01 under the 18-month rule. C stalls the browser channel.

**Dissent:** none

**Revisit when:** any @hpke/* version change (new C6 sign-off required), or upstream drops the fallback or the vendored code (B-28).

**Follow-ups:**
1. Security Architect: before the T-17 pin, explain the @hpke/core 1.9.0 provenance gap (the provenance names tag `hpke-js@1.8.0`; Medium). Then write the follow-up C6 amendment and sign-off, and add the C3a/C7a test lines to SR-9 and SR-13.
2. Tech Lead: add C7a.1–2 and C3a.1 to T-27 (esbuild metafile external check, guarded-import fixture, C3a input manifest). Add C7a.3 and C3a.3 to T-17. T-17 criteria 1–3 and 6 may start now; criteria 4, 5, 7 and 8 wait for the follow-up sign-off.
3. pyhpke 0.6.5 is signed. T-08 proceeds after V-01 merges, with the exact wheel/sdist hash pin and `open_base` mapping every exception to `OPEN_FAILED`.
4. Release: V-01's ADR section goes before the Security Architect's section in ADR 0011 (append conflict).
5. BACKLOG B-28: ask upstream to drop the Node ≤18 fallback and split out the vendored noble code.

## D-046 — Wave-0 contract amendments: httpx2, pnpm allowBuilds, semgrep rule narrowing, T-05 fixture ownership (INC-2, 2026-10-12)

Type: contract-amendment
Chair / decider: Tech Lead (PROCESS.md §6, local amendments)
Participants: Orchestrator, Software Engineers T-01, T-02, T-05

**Options considered**
For httpx: switch to httpx2, add a targeted warning filter, or pin older starlette/fastapi. For the others, only the rulings below.

**Decision:**
1. **T-01:** the dev dependency becomes `httpx2==2.13.1`. The Orchestrator verified the starlette 1.7.0 deprecation warning and httpx2 2.13.1 on PyPI (BSD-3-Clause, released 2026-09-23, github.com/pydantic/httpx2).
2. **T-02:** T-02 owns the root `pnpm-workspace.yaml` and adds `allowBuilds: {esbuild: false}`.
3. **T-05:** `tc-no-verification-skip` uses the regex `(?i)(?:skip|disable|bypass)_?verif|(?-i:(?!\bNO_VERIFIED_BUNDLE\b))no_?verif|insecure`. This exempts only the exact frozen code `NO_VERIFIED_BUNDLE`. All prior matches are preserved; the Tech Lead verified this with semgrep 1.178.0 `--test`.
4. **T-05:** T-05 owns the clean dependency-policy fixture, the 4 violation overlays and 1 test constant, so `CORE_RUNTIME_ALLOWED` can be emptied.

**Reasoning:**
- A warning filter would hide a real deprecation.
- Pinning an older stack would change the gateway runtime for a test-only problem.
- The narrowed rule exempts one exact identifier and does not weaken NFR-5/I13 detection.

**Dissent:** none

**Revisit when:** —

**Follow-ups:**
- Architect: change the INC-2-API §11 `httpx` row to `httpx2`.
- Tech Lead, in the D-043 pass: place the `INSECURE_TLS_ENVIRONMENT` error code so that it does not trip `tc-no-verification-skip`, or exempt it as exactly as `NO_VERIFIED_BUNDLE` is.

## D-047 — Security Architect APPROVES the D-043 design; SR-1, SR-9 and SR-13 updated (INC-2, 2026-10-12)

Type: gate-routing
Chair / decider: Orchestrator (on the Security Architect's verdict)
Participants: Architect, Security Architect

**Decision:** The D-043 design (INC-2-API rev 3 §16, ADR 0012; commit 0949533) is approved with one Low condition. L-1: the simulator's attacker JWKS key is generated fresh per state directory, is never committed, and signs only the `jwks_other_path*` cases. New test S6 checks that `/jwks` never contains the attacker modulus.

Q9 answers (a)–(e) are all confirmed: the production `jwks_uri` is a Core constant, so a change needs a Core patch release; the development path is `/jwks`; the attacker route is always served; `maxDiscoveryBytes` is inert, with a DEBT entry expiring at INC-5; the version is checked before the key set.

The Security Architect updated SR-1 (pin tests and build-time binding tests), SR-13 (`connect-src` lists only the JWKS origin) and SR-9/SR-13 (D-045 C3a/C7a lines). T-29 is now "mitigated by design (D-043, ADR 0012); test required".

**Traceability:** the §6.1 row changes only the Coverage type, Location and Status columns, which is within D-014's standing authority. The Architect applies it when the Core task, T-21, the vectors task and T-32 land. Requirement and Doc version are unchanged.

**Follow-ups:**
- Tech Lead D-043/D-045 pass: L-1/S6; C3a.2 (import-confinement lint rule) assigned to a task; the T-17 provenance evidence items 1–4.
- Add a DEBT entry for `maxDiscoveryBytes` when the Core task lands.

## D-048 — Human approves the T-03 spec/wire and spec/vectors content; Tech Lead D-043/D-045 pass recorded (INC-2, 2026-10-13)

Type: human-escalation + contract-amendment
Chair / decider: Human (T-03); Tech Lead (contracts)
Participants: Orchestrator, Code Reviewer, Security Reviewer, Tech Lead

**Decision:**
1. **T-03 approved by the human** for merge at inc-2/T-03-channel-wire 56ff7e9: spec/wire channel.cddl, channel-vectors.cddl and README; spec/vectors README, conftest.py and test_channel_suite.py.
   - Code Review: REQUEST_CHANGES (one Medium, negative cases unpinned), then APPROVE after 538e35d.
   - Security Review: APPROVE.
   - 56ff7e9 applies exactly the two pins both reviewers recommended: opens `aad_modified` → OPEN_FAILED and both directions' `aad_op_modified` → AUTH_FAILED. The Orchestrator verified the diff (2 files, +6/−5), so it is covered by both APPROVEs.
   - Merge after T-04 (WAVES).
2. **Tech Lead D-043/D-045 pass:**
   - New tasks:
     - T-33: Core trust profile v2 and pinned jwks_uri.
     - T-34: regenerate attestation vectors (FAST, human-gated).
     - T-35: `check-discovery` and the scheduled job; its fixture profile is human-gated.
     - T-36: QA updates to the INC-1 acceptance tests.
     - A new contract stub, test_profile_cli_contract.py.
   - Amended: T-08, T-16, T-17, T-18, T-20, T-21 (rewritten), T-25, T-26, T-27, T-30, T-31, T-32, API-TL and WAVES.
   - Merge unit MU-1 = T-33 + T-21 + T-34 + T-36: one combined green run, then consecutive merges.
   - Wave 1 now has 18 tasks in three batches.

**Open items:**
- **CI-2-4 (Architect):** Google's JWKS echoes the request Origin instead of `*`, and INC-2-API §16.3 says to stop in that case. It blocks T-21 and therefore MU-1, T-25, T-30, T-31, T-32 and T-35. The Tech Lead recommends `*`.
- **CI-2-5 (Architect):** the §16.6 run line cannot work under pnpm 11.5; TL-10 replaces it.
- **Security Architect:** confirm how T-17's provenance items 1–4 map to its sign-off.

**Dissent:** none

## D-049 — Human: scoped SR-9 age exception for h11 in the reference gateway (INC-2, 2026-10-13)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Security Reviewer (T-01)

**Options considered**
1. A scoped exception in `dependency_policy`, plus a DEBT entry.
2. Swap the gateway's ASGI server for one that does not use h11.
3. Declare examples/ out of scope for the age rule.

**Decision:** Option 1, chosen by the human. `framework.yaml` `security.dependency_policy` now admits h11 past the 18-month rule only as uvicorn's required dependency in examples/notes-app/gateway. The package must be OSI-licensed, exactly locked and pip-audit clean. It is re-checked at every lock change and at v1.0.0 release approval. Recorded as DEBT-3, expiring INC-5. (DEBT-2 is reserved for T-33's `maxDiscoveryBytes` entry.)

**Reasoning:**
- h11 0.16.0 (2025-04-24) leaves the window on 2026-10-24.
- No newer release exists.
- uvicorn hard-requires h11; httptools does not remove it from the closure.
- Only the untrusted example relay is affected. The library and the client packages are not.

**Dissent:** none

**Revisit when:** an h11 release, a uvicorn change that drops h11, or v1.0.0 release approval.

**Follow-ups:** T-05's dependency-policy tool must not flag h11 under this exception. If it does, the Tech Lead amends the tool's age check with an exact allow-list entry scoped to the gateway closure.

## D-050 — Wave 0 merged; G4 passes for INC-2 Wave 1 batch B1 (part) (INC-2, 2026-10-13)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Tech Lead, Release Engineer, QA

**Decision:** Wave 0 is complete on main c38d7fa:

| Item | Commit |
|---|---|
| T-04 | 7dc4f7f |
| T-03 | ac707fc |
| V-01 | a37d7d7 |
| V-02 | 94a2b40 |
| T-01 | ffbba1f |
| T-02 | 89e508b |
| T-05 | 9c657ec |
| QA acceptance tests | 5a853ee |

T-06 was satisfied on trunk (D-044). Every branch had Code and Security APPROVE.

G4 now passes for T-07, T-08, T-16 and T-17, and they start now. T-17 keeps its C6 hold point: the provenance evidence and the SA follow-up sign-off come before the lock change. T-21 and T-33 pass under the MU-1 exception and start once T-36 is authored on its branch. T-09, T-13, T-15 and T-37 wait for QA-acceptance-2.

**Reasoning:** The Orchestrator verified on main that ruff, mypy --strict (including the gateway), semgrep, pnpm typecheck and pnpm audit are green. The test suites fail only on expected-red rows. The Tech Lead re-ran the acceptance suites: 188 Python and 169 TS tests are red for the right reasons, as mapped in docs/qa/INC-2.md.

**Known red on trunk:** `pnpm -r lint` fails only on prettier for the vendored, hash-pinned tests/fixtures/rfc9180/test-vectors.json. The fix is assigned to T-37 A1 (`tests/.prettierignore` plus a hash test). Until T-37 merges, this one failure is expected in every task.

**Dissent:** none

## D-051 — Security Architect signs the T-17 C6 follow-up for @hpke/core 1.9.0 and @hpke/common 1.10.1 (INC-2, 2026-10-13)

Type: gate-routing
Chair / decider: Security Architect (C6, ADR 0011)
Participants: Orchestrator, Software Engineer (T-17)

**Decision:** Signed at the recorded integrities. The provenance gap is closed:
- the provenance ref `refs/tags/hpke-js@1.8.0` is the monorepo umbrella tag, at commit f9fbe3d;
- one workflow run published core 1.9.0, common 1.10.0 and hpke-js 1.8.0, and `packages/core/deno.jsonc` at that commit reads 1.9.0;
- the recomputed sha512, `dist.integrity` and the SLSA subject digests agree;
- `npm audit signatures` verifies both packages.

**Conditions:**
1. Before merge, T-17 re-runs evidence item 4 (bundle composition) on its final branch. Any difference goes back to the Security Architect.
2. `HPKE_INPUT_ALLOWLIST` lists only inputs with more than 0 bytes. Every `hash/**` input is capped at its recorded size.
3. The lock-file integrities equal the two recorded values.

**Rulings:**
- (a) C7a.1 is defined on bundle output: `outputs[…].imports` holds exactly one external, `crypto`/`dynamic-import`. Per-input attribution must be exactly algorithm.js ×1 and utils/misc.js ×2. Anything else exits 2. The Tech Lead amends T-27.
- (b) C3a.3 governs: HPKE uses only `globalThis.crypto.subtle`. QA changes the two SR14 acceptance tests that use `options.subtle`.

**Dissent:** none

## D-052 — Human approves the T-34 regenerated attestation vectors (MU-1) (INC-2, 2026-10-15)

Type: human-escalation
Chair / decider: Human
Participants: Orchestrator, Code Reviewer, Security Reviewer, Tech Lead

**Decision:** The human approved inc-2/T-34-attestation-vectors-v2 @ 6336fe1:
- spec/vectors/attestation/suite.cbor goes from 37 to 39 cases:
  - row 38 `jwks_other_path` and row 39 `jwks_other_path_same_kid` (T-29) are both UNTRUSTED_SIGNER;
  - the profiles are v2 with a pinned jwks_uri;
  - `http` holds JWKS URLs only;
  - the file holds public keys only.
- test_attestation_suite.py, including the attacker-key signature test.
- spec/vectors/README.md, as amended by A1/A2 and including the sentence explaining `cryptography`.
- Core contract CASE_COUNT 39.

Code Review APPROVE (round 2), Security Review APPROVE (round 2). It merges only with MU-1 (T-33, T-21, T-36), from one combined green run.

**Dissent:** none

## D-053 — Wave-1 review rulings: T-10, T-12, T-14, T-19, T-21, T-31, T-33 (INC-2, 2026-10-15)

Type: contract-amendment
Chair / decider: Tech Lead (§6); Architect (INC-2-API 9ab6975); Orchestrator (routing)
Participants: Code Reviewers, Security Reviewers, Software Engineers

**Decisions:**
- **T-10.** Revert 67c9bef (`TIMESTAMP_RANGE`). The Code Reviewer's objection stands: it adds an error to a frozen interface with no T-28 mapping, and T-28's skew check already bounds timestamps. Deferred as B-31.
- **T-12 A1.** Pending audit records are split into two classes:
  - `alert()` records and ALERT_CAP_REACHED: up to 256, never evicted by pre-principal ALERTs or AGGREGATEs;
  - pre-principal ALERTs and AGGREGATEs: up to 24.

  Other changes:
  - The drop log becomes `AUDIT_PENDING_DROPPED_<OUTCOME>`.
  - A backward clock jump ends the interval at its nominal end and logs AUDIT_CLOCK_BACKWARD.
  - The constructor enforces the §4.4 ranges.

  This fixes the Security Reviewer's Medium (T-20/SR-12: an anonymous flood during an outage evicted authenticated alerts).
- **T-14 A1 and T-31 A3.** These implement the INC-2-API §6/§9 amendment (9ab6975):
  - per-source in-flight cap; body-read deadline with 408;
  - IPv6 rate buckets keyed by /64;
  - control character in the path → 404;
  - uvicorn runs with `proxy_headers`, `server_header` and `access_log` set to False;
  - the T-14 Code Review Mediums: `/bundles%0A`, and slot release on cancel.
- **T-19 A2.** 408 maps to UNAVAILABLE. `referrerPolicy` is asserted. For the gitleaks false positive (a base64 test sentinel, fingerprint `be3e5bec…:fetch-transport.test.ts:generic-api-key:639`), T-19 creates `.gitleaksignore` holding that single fingerprint and renames the constant. History is not rewritten.
- **T-21 A2.** One final round outside the round limit, because a reviewer error caused the extra round. Approved.
- **T-33.** A round-1 Low fix (`new Uint8Array(x)`) introduced a High: a numeric nonce became all zeros. It was caught by the Code Reviewer and fixed in 0a50b77; both reviewers approve.

**Follow-ups:**
- Architect: align the INC-2-API §4.12 pending text, and add "no escapes / backslash refused" to the §6 gateway JSON contract.
- B-31, B-32 (Security Architect, INC-3).
- Retro: reviewer-recommended fixes need the same hostile-input tests.

**Dissent:** none

## D-054 — INC-2 Wave 1 merged, including MU-1 (D-043) (INC-2, 2026-10-15)

Type: gate-routing
Chair / decider: Orchestrator
Participants: Release Engineer, Code and Security Reviewers

**Decision:** All 18 Wave 1 items are on main at 34d1193: T-07, T-08, T-09, T-10, T-11, T-12, T-13, T-14, T-15, T-16, T-17, T-18, T-19, T-20 and T-37. MU-1 was merged as a unit after a combined green run on inc-2/MU-1-integration: T-33 (8e06da8), T-21 (6645a9a), T-34 (10e37c2, human-approved in D-052) and T-36 (7d337f8). QA-4..7 were merged along with them. Every task had Code and Security APPROVE. T-03 and T-18 got pin-only and clamp-only rounds, verified by the Orchestrator.

**Evidence on main 34d1193:**
- Python: 133 failed, 3999 passed, 24 errors. Every failure is an expected red for unmerged tasks (T-22..T-32, T-35) or the missing channel/suite.cbor.
- Core TS: 1272 of 1272 pass. The tests package has 52 failures, all expected red. Web has no failures.
- spec/vectors attestation: 94 green.
- Clean: ruff, mypy --strict, semgrep, pnpm lint/typecheck/audit, dependency_policy (`--today 2026-10-25` exits 0, so h11 is handled), and gitleaks (HEAD).
- DEBT-2 is dated.

**Notable review outcomes (for the retro):**
- **T-02:** mutable branded-bundle key bytes, Medium. Fixed with copy-on-read.
- **T-33:** a round-1 fix introduced a High (a numeric nonce became all zero bytes). The Code Review caught it; the Security Review had dismissed it.
- **T-12:** an anonymous flood during an outage could evict authenticated alerts (High per Code Review). Fixed with two pending classes and a single pending ALERT_CAP_REACHED.
- **T-14:** slow-body DoS and a `/bundles%0A` route bypass. Fixed under the §6 amendment.
- **T-20:** the vault no longer derives from create-time PRF output (Architect, option b), which removes a path to permanent `cs` loss.
- **T-21:** one reviewer-error round outside the round limit, approved by the Tech Lead.
- **T-10:** a reviewer conflict, resolved by revert (B-31).
- **Gitleaks:** false positives handled with single `.gitleaksignore` fingerprints; history was not rewritten.

**Dissent:** none

## D-055 — lint_command runs semgrep with --disable-nosem (INC-2, 2026-10-15)

Type: gate-routing
Chair / decider: Orchestrator (framework.yaml commands)
Participants: Software Engineer (T-27)

**Decision:** `lint_command` now passes `--disable-nosem` to semgrep, so a `// nosemgrep` or `# nosemgrep` comment can no longer silence a security rule. T-27 showed that such a comment hid a banned `@hpke/common` import. The Orchestrator verified that the full scan on main exits 0 with the flag, and the repo source contains no nosem comments. The Tech Lead adds the same flag to the CI semgrep step, which T-27 owns.

**Dissent:** none
