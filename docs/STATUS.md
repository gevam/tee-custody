# Status — tee-custody

Updated: 2026-10-05 (INC-1 fix wave before G7) by Orchestrator

## Where we are
Stage: INC-1 Wave 4 (G6 Low-defect fixes, D-031)
Last gate passed: G4 (Wave 1)   Next gate: G5/G6 re-check after Wave 4, then G7, G8
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
| Task | Wave | Tier | State | Branch | Notes |
|---|---|---|---|---|---|
| Waves 0–3: T-01..T-20 + V-01 | 0–3 | — | all merged (main 84ba17a) | — | T-18 vectors human-approved (D-030) |
| Wave 4: fixes for D-01..D-04 + vectors-overwrite guard | 4 | TBD | contracts being written | — | D-031 (human: fix all now) |

QA: Phase 2 done — all INC-1 requirements pass; defects Critical 0 / High 0 / Medium 0 / Low 4 (D-01..D-04); docs/qa/INC-1.md
Reviews: every INC-1 branch approved by Code + Security Reviewer before merge.

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| — | | | | |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| INC-4 VSS | Approve the concrete Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dependency change | No, before INC-4 | Review then | Decide at Security Architect review |
| semgrep in lint_command | Append semgrep to framework.yaml lint_command when T-14 merges (R-11) | No | — | Orchestrator applies at T-14 merge |
| framework gap | `sdlc/roles/_security-constraints.md` referenced by framework.yaml but missing; Orchestrator passes the spec explicitly | No | Add fragment / ignore | Add when convenient |

## Decisions this increment
- D-014: standing authority for traceability coverage columns. D-015: test/coverage commands cover tests/ and teecustody_sim.
- D-016: constraint-deviation (human) — §6.8 via Google-verified key_ids (T-22, Low residual).
- D-017: CI-1..CI-10 rulings; ADR 0009 (own RS256 JWS framing) and ADR 0010 (own TS CBOR codec, replaces cbor-x) — both Accepted by Security Architect.
- D-018: G4 per wave; Wave 0 passed.
- D-019: SR-9 release-age rule scoped to shipped/build deps (human).
- D-020: human approved T-03 spec/wire content. D-021: G4 passed for Wave 1.
- D-026/D-030: human approved T-20 and T-18 spec/vectors. D-027: T-20 re-applied after mistaken revert. D-028: semgrep in lint_command. D-029: T-19 scoped round 3; T-16 merged by Orchestrator (human). D-031: fix all G6 Lows in INC-1.
- D-023: max_engineers 8. D-024: T-05 scoped round 3. D-025: T-20 added (§G missing-claim rows; INC-1 18 → 20 tasks, +11%).
- D-022: signer-key dedup at profile generation (T-17; INC-5 tool via B-05). Shared CBOR depth ceiling 64 (T-04/T-09). BACKLOG B-06 (Fetcher URL/adapter controls) required for INC-2.

## Debt
Open entries: 0   Expired-unscheduled: 0

## Spend
| Role | Tokens this increment | Tokens total | Budget |
|---|---:|---:|---|
| Tech Lead | ~580k | ~580k | Unlimited |
| Architect | ~450k | ~645k | Unlimited |
| Security Architect | ~260k | ~460k | Unlimited |
| Engineers (V-01) | ~105k | ~105k | Unlimited |
| Total (this session, approx.) | ~1.4M | ~1.8M | Unlimited |
