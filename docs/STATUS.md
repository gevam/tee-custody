# Status — tee-custody

Updated: 2026-09-29 at G3 by Orchestrator

## Where we are
Stage: INC-1 work breakdown (preparing)
Last gate passed: G3   Next gate: G4
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
Tasks not yet decomposed. Before Tech Lead starts: Architect/Security Architect clerical follow-ups from G3 (D-013), and a trunk baseline commit (repo has no commits; local branch is `master`, framework trunk is `main`).

QA: not-started
Reviews: —

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| Trunk baseline | G4 (worktrees, "fails on trunk") | Orchestrator | G3 | Create initial local commit on `main`; no push |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| INC-4 VSS | Approve the concrete Feldman VSS / Ristretto255 proposal if it needs a constraint deviation or crypto dependency change | No, before INC-4 | Review then | Decide at the Security Architect review |
| spec/wire | INC-1 creates `spec/wire` CDDL and `spec/vectors`; every such change is always-human | No, at INC-1 merge | Approve at G7/G8 | Review the INC-1 wire PR before merge |

## Decisions this stage
- D-005/D-006: G3 findings routed to Architect twice; closed in re-review 2.
- D-007: audit may carry actor_client_id, subject_client_id, recovery_id (human, §11 interpretation).
- D-008: `recover_cancel` reserved. D-009: INCREMENTS.md is the sole increment source (blocker closed).
- D-010: human accepted residual risks T-19 (High), T-13, T-01, T-15, T-17, T-05, T-20.
- D-011: T-21 mitigated by a host admission hook in INC-4. D-012: `count` on aggregate audit records.
- D-013: G3 passed.

## Debt
Open entries: 0   Expired-unscheduled: 0

## Spend
| Role | Tokens this increment | Tokens total | Budget |
|---|---:|---:|---|
| Security Architect | ~200k (G3 re-reviews) | not instrumented before this session | Unlimited |
| Architect | ~195k (G3 fixes) | not instrumented before this session | Unlimited |
| Total | ~395k this session | not instrumented | Unlimited |
