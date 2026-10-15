# Status — tee-custody

Updated: 2026-10-15 (INC-2 complete: G5–G8 passed, `inc-2` tagged locally) by Orchestrator

## Where we are
Stage: INC-2 retrospective (§3.9), then apply accepted changes and INC-3 work breakdown
Last gate passed: G8 for INC-2 (D-080)   Next: retro → INC-3 G4
Increments merged: `inc-1` (957ed82), `inc-2` (0e20909) — both local annotated tags, not pushed

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

## INC-2 — Encrypted channel and browser client (done)
| Item | State |
|---|---|
| Tasks | T-01..T-42, V-01, V-02 + QA items (QA-acceptance, QA-D-01, QA-T-38, QA-T-39, QA-I7, QA-exec/QA-T-40, QA-G6), all merged; T-38..T-42 added mid-increment (D-064, D-069, D-071, D-074) |
| Tests on main | Python 4842, Core 1479, web 771, tests 673, spec/vectors 236 — all green; browser suite green on Chromium + Firefox (WebKit needs CI) |
| Coverage | 100% statements/branches/lines: Python (teecustody, teecustody_sim, notes_gateway), @teecustody/core, @teecustody/web (D-077) |
| QA | G6 PASS (D-079); D-01..D-07 found and closed; 0 open defects |
| Security | every branch Code+Security APPROVE; G7 increment pass, 0 findings ≥ Medium (D-078) |
| Human decisions this increment | D-043 (§6.1 deviation: pinned jwks_uri), D-045 (@hpke admitted), D-048, D-049 (h11), D-052/D-058 (vectors), D-061 (fixture profile) |
| Design changes | ADR 0013 bounded clock skew (D-064); ADR 0011 C8 bounded X25519 keygen retry (D-069); gateway server hardening §6 (D-071, D-074) |
| Traceability | no INC-2 GAP rows; 13 GAP rows remain for INC-3..INC-5 |
| Required for INC-3 | B-24, B-25, B-26 (ordering — Core posts frames in seal-completion order), B-27, B-33, B-41 (pre-key collision), B-51 (bundle brand ↔ trust profile) |

## Blockers
None.

## Open questions for the human
| Id | Question | Blocking? | Options | Recommendation |
|---|---|---|---|---|
| Push | Push main + `inc-1` + `inc-2` to origin? (first CI run; §13.11 evidence; WebKit browser evidence) | No | Push / keep local | Push when convenient |
| Cleanup | Remove merged git worktrees (~89 under /home/geva/code/wt-*) and the two `/home/geva/code/tmp/T-30-*` scratch dirs | No | Remove / keep | Remove (all work is merged) |
| Clock | WSL2 host clock is stepped by systemd-timesyncd + Hyper-V (D-02); disable one source? | No | Disable timesyncd / leave | Optional; ADR 0013 makes tests tolerant |
| INC-4 VSS | Feldman VSS / Ristretto255 proposal if it needs a deviation or crypto dep change | No, before INC-4 | Review then | Decide at Security Architect review |
| framework gap | `sdlc/roles/_security-constraints.md` referenced but missing | No | Add / ignore | Add when convenient |

## Decisions this increment
INC-2: D-039..D-080 — notable: D-077..D-080 (gates G5–G8), D-064 (ADR 0013), D-069 (ADR 0011 C8), D-071/D-074 (gateway defects), D-061 (T-35 fixture human-approved), D-062 (MU-2), D-064 (ADR 0013, D-02), D-058 (T-30 vectors approved), D-049 (h11 exception), D-052 (T-34 vectors approved), D-053 (Wave-1 rulings), D-054 (Wave 1 merged), D-046 (Wave-0 contract fixes), D-047 (SA approves D-043 design), D-048 (T-03 spec approved), D-041 (CDDL approved), D-043 (§6.1 constraint-deviation: pinned jwks_uri), D-045 (@hpke/* admitted, framework.yaml exception). INC-1: D-014..D-037 — notable: D-016 (§6.8 constraint-deviation), D-019 (SR-9 scope), D-020/D-026/D-030 (spec approvals), D-022 (signer-key dedup at generation), D-023 (8 engineers), D-025 (T-20), D-027 (mistaken revert reverted), D-031 (fix all Lows), D-034..D-037 (gates).

## Debt / backlog
DEBT.md open: DEBT-2 (maxDiscoveryBytes, INC-5), DEBT-3 (h11, INC-5). BACKLOG.md: B-01..B-52 Required for INC-3: B-24..B-27, B-33, B-41, B-51; Required for INC-5: B-05, B-30.

## Spend
| Role | Tokens INC-1 (approx.) |
|---|---:|
| Engineers (STRONG/MID/FAST) | ~5.5M |
| Code + Security Reviewers | ~5.0M |
| Tech Lead / Architect / Security Architect | ~1.5M |
| QA / Release Engineer | ~1.2M |
| Total (approx., from agent usage reports) | ~13M |
Budget: unlimited.
