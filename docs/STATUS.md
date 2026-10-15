# Status — tee-custody

Updated: 2026-10-15 (INC-2 Wave 2 merged; T-28 merged, T-29 in re-review) by Orchestrator

## Where we are
Stage: INC-2 wave 3 implementation
Last gate passed: Wave 2 merged (D-056/D-057)   Next gate: T-29 merge, then T-31/T-32/T-35, G5/G6/G7/G8
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

| Item | State |
|---|---|
| Wave 2 (T-22..T-27, T-25 CLI) | all merged (D-056, D-057) |
| T-30 channel vectors | merged 085eccb (human-approved D-058, sha256 verified) |
| T-28 ChannelServer | merged fbea1dd (D-059), with QA-acceptance-8 f94e743 |
| T-29 RunLoop | round-2 Code + Security re-review in progress |
| T-31 e2e harness | starts after T-29 merges |
| T-32 Playwright CSP harness | after T-31 |
| T-35 check-discovery + scheduled job | pending (fixture profile human-gated) |

Main at e465784: spec/vectors 236 passed; Python 15 failed / 11 errors / 4612 passed (all T-29 expected red); pnpm 18 FR-4 e2e reds (HARNESS_MISSING, T-31); ruff/mypy/semgrep/gitleaks clean.

## Blockers
None.

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` to origin? (first CI run; §13.11 evidence) | No | Push / keep local | Push when convenient |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-059 — notable: D-058 (T-30 vectors approved), D-059 (T-28 verdicts), D-049 (h11 exception), D-052 (T-34 vectors approved), D-053 (Wave-1 rulings), D-054 (Wave 1 merged), D-046 (Wave-0 contract fixes), D-047 (SA approves D-043 design), D-048 (T-03 spec approved), D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri), D-045 (@hpke/* admitted, framework.yaml exception). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: DEBT-2 (maxDiscoveryBytes, INC-5), DEBT-3 (h11, INC-5). BACKLOG.md: B-01..B-36 (B-24..B-27 Required for INC-3; B-30 Required for INC-5); required for INC-2 contracts: B-06 (Fetcher URL + adapter controls), B-08 (refresh backoff), B-13 (runtime VerifiedAttestation brand); B-05 for INC-5.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
