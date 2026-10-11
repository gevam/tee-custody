# Status — tee-custody

Updated: 2026-10-11 (INC-2 Wave 0, resumed after restart) by Orchestrator

## Where we are
Stage: INC-2 wave 0 implementation
Last gate passed: G4 (INC-2 Wave 0, D-042)   Next gate: G4 (Wave 1), G5
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
34 items (T-01..T-32, V-01, V-02) in 6 waves (docs/tasks/INC-2/WAVES.md). Wave 0: T-01..T-05, V-02 resumed (engineers re-spawned 2026-10-11); T-06 content on trunk (4c823a3, D-044); V-01 done, evidence awaiting Security Architect C6 sign-off. Human-gated: T-03 (channel CDDL/harness), T-30 (channel vectors). Design: docs/INC-2-API.md (CDDL approved D-041).

## Blockers
| Id | Blocking | Owner | Since | Next action |
|---|---|---|---|---|
| CI-2-1 | T-21, T-25, T-31, T-32 (browser attestation path) | Architect → Tech Lead | 2026-10-06 | Human chose Option A (D-043: pin exact jwks_uri, no runtime discovery); Architect amending INC-2-API, then Tech Lead amends tasks |
| V-01-C7 | T-17, T-27 (@hpke/core adoption) | Security Architect → human? | 2026-10-11 | @hpke/core browser bundle keeps `import("crypto")` (C7 fail); @hpke/common vendors pure-JS noble code (C3 vs framework.yaml forbidden_dependencies); SA ruling in progress |

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` to origin? (first CI run; §13.11 evidence) | No | Push / keep local | Push when convenient |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-044 — notable: D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: 0. BACKLOG.md: B-01..B-23; required for INC-2 contracts: B-06 (Fetcher URL + adapter controls), B-08 (refresh backoff), B-13 (runtime VerifiedAttestation brand); B-05 for INC-5.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
