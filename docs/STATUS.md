# Status — tee-custody

Updated: 2026-09-30 at G4 (INC-1 Wave 0) by Orchestrator

## Where we are
Stage: INC-1 wave 0 implementation
Last gate passed: G4 (Wave 0; D-018 — Wave 1 re-checked after QA authors acceptance tests)   Next gate: G5
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
| Task | Wave | Tier | State | Branch | Notes |
|---|---|---|---|---|---|
| T-01 Python tooling + API stubs | 0 | STRONG | in-progress | inc-1/T-01-py-tooling | |
| T-02 TS tooling + Core stubs | 0 | STRONG | in-progress | inc-1/T-02-ts-tooling | |
| T-03 Wire binding + vectors harness | 0 | STRONG | in-progress | inc-1/T-03-wire-binding | Human approval before merge (spec/wire) |
| V-01 Confidential Space facts | 0 | STRONG | F-01..F-15 done; F-16 re-run in progress | inc-1/V-01-facts | |
| T-04..T-14 | 1 | STRONG/MID | not started | — | Needs QA acceptance tests first |
| T-15..T-17 | 2 | STRONG | not started | — | |
| T-18 vectors generation | 3 | FAST | not started | — | Human approval before merge (spec/vectors) |

QA: not-started (authors after Wave 0 merges)
Reviews: —

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| — | | | | |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| spec/wire | Approve T-03's `spec/wire` + `spec/vectors` content (always-human) | Yes, for T-03 merge | Approve / request changes | Summary comes to you when T-03 reports |
| INC-4 VSS | Approve the concrete Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dependency change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced by framework.yaml but missing; Orchestrator passes the spec explicitly | No | Add fragment / ignore | Add when convenient |

## Decisions this increment
- D-014: standing authority for traceability coverage columns. D-015: test/coverage commands cover tests/ and teecustody_sim.
- D-016: constraint-deviation (human) — §6.8 via Google-verified key_ids (T-22, Low residual).
- D-017: CI-1..CI-10 rulings; ADR 0009 (own RS256 JWS framing) and ADR 0010 (own TS CBOR codec, replaces cbor-x) — both Accepted by Security Architect.
- D-018: G4 per wave; Wave 0 passed.

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
