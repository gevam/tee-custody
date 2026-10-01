# Status — tee-custody

Updated: 2026-10-01 (INC-1 Wave 1 closing / Wave 2) by Orchestrator

## Where we are
Stage: INC-1 waves 1–2 implementation and review
Last gate passed: G4 (Wave 1, D-021)   Next gate: G5
Increments merged: none

## Current increment — INC-1 (Attestation foundation)
| Task | Wave | Tier | State | Branch | Notes |
|---|---|---|---|---|---|
| T-01, T-02, T-03, V-01 | 0 | STRONG | merged | — | Wave 0 complete |
| T-04 Python CBOR codec | 1 | STRONG | merged (8283c0a) | | depth ceiling 64 |
| T-05 Allow-listed logger | 1 | MID | merged (edc0ade) | | round 3 per D-024 |
| T-06 Workload attestation lifecycle | 1 | STRONG | merged (d6d545d) | | scoped round 3 |
| T-07 Sim keys + token minting | 1 | STRONG | merged (f8cbe99) | | |
| T-08 Sim issuer + launcher | 1 | STRONG | merged (05b65c1) | | §15.5 criterion 4a |
| T-09 TS CBOR codec | 1 | STRONG | merged (100ab4d) | | |
| T-10 Token + profile parsing | 1 | STRONG | merged (3af4c0e) | | |
| T-11 §6.1–6.2 | 1 | STRONG | merged (6b628f3) | | |
| T-12 §6.3–6.7 | 1 | STRONG | merged (8ed8f2c) | | |
| T-13 §6.8 | 1 | STRONG | merged (0596b77) | | D-016 |
| T-14 CI, scanners, semgrep | 1 | STRONG | review fixes round 1 | inc-1/T-14-ci-policy | CR 2 High, SR 4 Medium |
| T-15 verifyAttestation + SR-12 | 2 | STRONG | merging | inc-1/T-15-ts-verify | both approved |
| T-16 Sim CLI + runtime | 2 | STRONG | in-progress | inc-1/T-16-sim-cli | |
| T-17 Dev profile + vector generator | 2 | STRONG | review fixes round 1 | inc-1/T-17-sim-vectors | + D-022/§G amendments |
| T-19 §15.5 hardening + flaky test | 2 | STRONG | in-progress | inc-1/T-19-sim-hardening | follow-up to T-08 |
| T-20 §G rows 29–37 | 2 | STRONG | in-progress | inc-1/T-20-sim-missing-claim-cases | **human approval** (spec/vectors test file), D-025 |
| T-18 vectors generation | 3 | FAST | not started | — | **human approval** (spec/vectors) |

QA: acceptance tests on main; 3 QA defects fixed (2 merged, 1 on inc-1/qa-acceptance e24a84c pending merge)
Reviews: Wave 1 merged except T-14. Engineer cap 8 (D-023).

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
