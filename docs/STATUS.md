# Status — tee-custody

Updated: 2026-09-30 during G4 (INC-1) by Orchestrator

## Where we are
Stage: INC-1 work breakdown — G4 blocked on contract issues
Last gate passed: G3   Next gate: G4
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
18 tasks + V-01 in 4 waves (docs/tasks/INC-1/WAVES.md); committed on `main` (dd50b4f); V-01 facts verified on branch inc-1/V-01-facts. No engineer started.

QA: not-started (authors after Wave 0)
Reviews: —

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| ADR 0009 (JWS) / ADR 0010 (TS CBOR) sign-off | Wave 0 | Security Architect | 2026-09-30 | Review in progress |
| F-12 design finalization (D-016 option a) | T-13, Wave 0 types | Architect | 2026-09-30 | In progress |
| Contract amendments (CI rulings, D-016, V-01 rows) | G4 | Tech Lead | 2026-09-30 | After the two above |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| INC-4 VSS | Approve the concrete Feldman VSS / Ristretto255 proposal if it needs a constraint deviation or crypto dependency change | No, before INC-4 | Review then | Decide at the Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` is referenced by framework.yaml but missing; Orchestrator passes the spec explicitly meanwhile | No | Add the fragment / ignore | Add it when convenient |
| spec/wire | INC-1 creates (T-03, T-18) `spec/wire` CDDL and `spec/vectors`; every such change is always-human | No, at INC-1 merge | Approve at G7/G8 | Review the INC-1 wire PR before merge |

## Decisions this stage
- D-005/D-006: G3 findings routed to Architect twice; closed in re-review 2.
- D-007: audit may carry actor_client_id, subject_client_id, recovery_id (human, §11 interpretation).
- D-008: `recover_cancel` reserved. D-009: INCREMENTS.md is the sole increment source (blocker closed).
- D-010: human accepted residual risks T-19 (High), T-13, T-01, T-15, T-17, T-05, T-20.
- D-011: T-21 mitigated by a host admission hook in INC-4. D-012: `count` on aggregate audit records.
- D-013: G3 passed. D-014: standing authority for traceability coverage columns. D-015: test/coverage commands include tests/ and teecustody_sim.
- D-016: constraint-deviation (human): §6.8 satisfied via Google-verified key_ids. D-017: CI-1..CI-10 rulings accepted.

## Debt
Open entries: 0   Expired-unscheduled: 0

## Spend
| Role | Tokens this increment | Tokens total | Budget |
|---|---:|---:|---|
| Security Architect | ~200k (G3 re-reviews) | not instrumented before this session | Unlimited |
| Architect | ~195k (G3 fixes) | not instrumented before this session | Unlimited |
| Total | ~395k this session | not instrumented | Unlimited |
