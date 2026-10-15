# Status — tee-custody

Updated: 2026-10-15 (INC-2 all tasks merged except T-32) by Orchestrator

## Where we are
Stage: INC-2 wave 5 (T-32 round 2), then G5/G6/G7/G8 and retro
Last gate passed: all of Waves 0–4 merged (D-050..D-067)   Next gate: T-32 merge → G5
Increments merged: `inc-1` (local tag on 957ed82, not pushed)

## INC-1 — Attestation foundation (done)
| Item | State |
|---|---|
| Waves 0–3, T-30 vectors, T-35 (fixture human-approved D-061) | merged |
| T-28 ChannelServer, T-29 RunLoop | merged (D-059, D-060; T-29 final round under TL A2) |
| MU-2: T-31 e2e harness + QA D-01 | merged 03e0ad3 (D-062, D-063, D-065) |
| T-38 ADR 0013 bounded clock skew (fixes D-02) | merged c9f9784 (D-064, D-066) |
| QA-I7 queue-content acceptance tests | merged fb8f608 (D-067); gitleaks FP ignored 3f1f5db |
| T-32 Playwright CSP harness | round 2 in progress (CR High: Firefox favicon check vacuous at Playwright 1.63.0) |
| Defects | D-01 closed, D-02 closed (environmental WSL2 clock steps + ADR 0013) |
| Traceability | no INC-2 GAP rows (I7 closed 9ee6eaa; §6.1/§6.4 updated e940339) |

Main: all suites green — Python 4502, Core 1478, web 715, tests 652, spec/vectors 236; lint/type/semgrep/gitleaks clean.

## Blockers
None.

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` to origin? (first CI run; §13.11 evidence) | No | Push / keep local | Push when convenient |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-067 — notable: D-061 (T-35 fixture human-approved), D-062 (MU-2), D-064 (ADR 0013, D-02), D-058 (T-30 vectors approved), D-049 (h11 exception), D-052 (T-34 vectors approved), D-053 (Wave-1 rulings), D-054 (Wave 1 merged), D-046 (Wave-0 contract fixes), D-047 (SA approves D-043 design), D-048 (T-03 spec approved), D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri), D-045 (@hpke/* admitted, framework.yaml exception). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: DEBT-2 (maxDiscoveryBytes, INC-5), DEBT-3 (h11, INC-5). BACKLOG.md: B-01..B-44 (B-41 pre-key collision Required INC-3) (B-24..B-27 Required for INC-3; B-30 Required for INC-5); required for INC-2 contracts: B-06 (Fetcher URL + adapter controls), B-08 (refresh backoff), B-13 (runtime VerifiedAttestation brand); B-05 for INC-5.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
