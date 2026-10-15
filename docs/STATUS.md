# Status — tee-custody

Updated: 2026-10-15 (INC-2 Wave 1 merged; Wave 2 running) by Orchestrator

## Where we are
Stage: INC-2 wave 2 implementation
Last gate passed: Wave 1 merged (D-054)   Next gate: Wave 2 merges, then Waves 3–5, G5/G6/G7/G8
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

Wave 0: complete (D-050). Wave 1: complete on main 34d1193 (D-054), incl. MU-1 (D-043 pinned jwks_uri; vectors human-approved D-052).

| Wave 2 item | State |
|---|---|
| T-22 pre-keys + bundle build | merged dbba6ce (D-056) |
| T-23 sessions, T2cSealer, session table | merged (D-056) |
| T-24 in-memory queue + audit sink | merged (D-056) |
| T-25 channel vector generator + CLI | Code + Security APPROVE (D-056); merging |
| T-26 Core ChannelClient/Session | merged e0bef2f (D-056) |
| T-27 SR-13 bundle scan | round 3 confirmations pending |
| T-28 ChannelServer, T-29 RunLoop (Wave 3) | engineers running |
| T-30 channel vectors (human-gated), T-31, T-32, T-35 | pending |

Main at 34d1193: Python 133 failed / 3999 passed (all expected red), Core 1272/1272, all lint/type/security gates green.

## Blockers
None.

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` to origin? (first CI run; §13.11 evidence) | No | Push / keep local | Push when convenient |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-054 — notable: D-049 (h11 exception), D-052 (T-34 vectors approved), D-053 (Wave-1 rulings), D-054 (Wave 1 merged), D-046 (Wave-0 contract fixes), D-047 (SA approves D-043 design), D-048 (T-03 spec approved), D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri), D-045 (@hpke/* admitted, framework.yaml exception). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: DEBT-2 (maxDiscoveryBytes, INC-5), DEBT-3 (h11, INC-5). BACKLOG.md: B-01..B-32 (B-24..B-27 Required for INC-3; B-30 Required for INC-5); required for INC-2 contracts: B-06 (Fetcher URL + adapter controls), B-08 (refresh backoff), B-13 (runtime VerifiedAttestation brand); B-05 for INC-5.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
