# Status — tee-custody

Updated: 2026-10-01 (INC-1 Wave 1 in progress) by Orchestrator

## Where we are
Stage: INC-1 wave 1 implementation (batch 1 of 3)
Last gate passed: G4 (Wave 1, D-021)   Next gate: G5
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
| Task | Wave | Tier | State | Branch | Notes |
|---|---|---|---|---|---|
| T-01 Python tooling + API stubs | 0 | STRONG | merged (e22c759) | inc-1/T-01-py-tooling | |
| T-02 TS tooling + Core stubs | 0 | STRONG | merged (815f379) | inc-1/T-02-ts-tooling | |
| T-03 Wire binding + vectors harness | 0 | STRONG | merged (c9d0e95) | inc-1/T-03-wire-binding | Human-approved D-020 |
| V-01 Confidential Space facts | 0 | STRONG | merged (92538a0) | inc-1/V-01-facts | |
| T-04 Python CBOR codec | 1 | STRONG | review fixes round 1 (ceiling 64 + precedence tests) | inc-1/T-04-py-wire | CR DESIGN_ISSUE resolved by contract amendment b454153 |
| T-05 Allow-listed logger | 1 | MID | queued | — | |
| T-06 Workload attestation lifecycle | 1 | STRONG | in-progress | inc-1/T-06-py-attest | |
| T-07 Sim keys + token minting | 1 | STRONG | queued: review fixes round 1 | inc-1/T-07-sim-token | SR approve; CR 2 Medium |
| T-08 Sim issuer + launcher | 1 | STRONG | in-progress | inc-1/T-08-sim-servers | |
| T-09 TS CBOR codec | 1 | STRONG | in review (SR approve; CR pending) | inc-1/T-09-ts-wire | + ceiling-64 additions pending |
| T-10 Token + trust-profile parsing | 1 | STRONG | merged (3af4c0e) | inc-1/T-10-ts-parse | |
| T-11 §6.1 signature + §6.2 issuer | 1 | STRONG | queued: review fixes round 1 | inc-1/T-11-ts-signature | SR approve; CR 2 Medium |
| T-12 §6.3–§6.7 claim checks | 1 | STRONG | in review | inc-1/T-12-ts-claims | |
| T-13 §6.8 image check | 1 | STRONG | in-progress | inc-1/T-13-ts-image | |
| T-14 CI, scanners, semgrep | 1 | STRONG | queued | — | |
| T-15..T-17 | 2 | STRONG | not started | — | |
| T-18 vectors generation | 3 | FAST | not started | — | Human approval before merge (spec/vectors) |

QA: acceptance tests authored and merged (05ce1de): 79 Python + 202 TS cases, all red on trunk
Reviews: T-10 merged; T-04/T-07/T-11 changes requested (round 1); T-09, T-12 in review. Engineer cap 4 — fix rounds queue ahead of new tasks.

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
