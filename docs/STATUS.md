# Status — tee-custody

Updated: 2026-10-13 (INC-2 Wave 1 started) by Orchestrator

## Where we are
Stage: INC-2 wave 1 implementation (batch B1)
Last gate passed: G4 (INC-2 Wave 1 B1 part, D-050)   Next gate: G4 (rest of Wave 1), G5
Increments merged: `inc-1` (local tag on 957ed82, not pushed)

## INC-1 — Attestation foundation (done)
| Item | State |
|---|---|
| Tasks | 24 merged (T-01..T-24 + V-01; T-19/T-20 added mid-increment, T-21/T-23/T-24 fix wave per D-031) |
| Tests on main | Python 1806, Core TS 901, tests pkg 323, spec/vectors 212 — all green |
| Coverage | 100% line+branch on teecustody, teecustody_sim, @teecustody/core |
| QA | all INC-1 acceptance criteria pass; D-01..D-04 found and closed; 0 open defects |
| Security | every branch Code+Security APPROVE; G7 increment pass, no finding ≥ Medium |
| Human-approved spec content | spec/wire (D-020), T-20 rows (D-026), vectors (D-030), README line (D-032) |
| Traceability | §6.2–§6.9, §13.2, §13.9 covered; §6.1, I1, I13, §13.1, §13.10 partial; rest GAP for later increments |

## INC-2 — Encrypted channel and browser client
38 items (T-01..T-36, V-01, V-02) in 6 waves (docs/tasks/INC-2/WAVES.md); merge unit MU-1 = T-33 + T-21 + T-34 + T-36 (D-043 pinned jwks_uri).

Wave 0: complete on main c38d7fa (D-050), all branches Code+Security APPROVE.

| Wave 1 item | State |
|---|---|
| T-07 Python codec | running |
| T-08 pyhpke + open_base | running |
| T-16 Core bundle verify/select | running |
| T-17 @hpke/core + WebCrypto | running; C6 hold point before lock change |
| T-21, T-33 (MU-1) | start after T-36 authored |
| T-09, T-13, T-15, T-37 | waiting for QA acceptance tests (QA-acceptance-2 in progress) |
| T-36 (QA, MU-1) | authoring |
| T-10..T-14, T-18..T-20, T-34 | batches B2/B3 |

Known red on trunk: prettier on vendored tests/fixtures/rfc9180/test-vectors.json until T-37 merges.

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| V-01-C7 | T-17 crit. 4/5/7/8 | T-17 engineer → Security Architect | 2026-10-11 | @hpke/* admitted (D-045); T-17 must record provenance evidence 1–5 and get SA C6 follow-up sign-off before the lock change |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` to origin? (first CI run; §13.11 evidence) | No | Push / keep local | Push when convenient |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| h11 age | uvicorn's required HTTP parser h11 0.16.0 (2025-04-24) leaves the SR-9 18-month window on 2026-10-24; gateway runtime closure | Before INC-2 merge | see escalation | pending |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-048 — notable: D-046 (Wave-0 contract fixes), D-047 (SA approves D-043 design), D-048 (T-03 spec approved), D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri), D-045 (@hpke/* admitted, framework.yaml exception). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: 0. BACKLOG.md: B-01..B-28 (B-24..B-27 Required for INC-3); required for INC-2 contracts: B-06 (Fetcher URL + adapter controls), B-08 (refresh backoff), B-13 (runtime VerifiedAttestation brand); B-05 for INC-5.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
