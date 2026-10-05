# Retrospective — INC-1

Date: 2026-10-05   Tag: inc-1 (local)   Author: retrospective-analyst

## By the numbers
| Metric | Value |
|---|---|
| Tasks / waves | 24 items (23 tasks + V-01), 5 waves; planned 18, grew about 33% (T-19, T-20 mid-increment; T-21/T-23/T-24 fix wave, D-031). D-025 judged 11% at 20 tasks, below the 30% trigger; final growth was not re-assessed against `escalation.effort_growth_pct` |
| CONTRACT_ISSUE returns / contract amendments | At least 1 CONTRACT_ISSUE (T-10, stub-throw tests) plus CI-1..CI-10 against ARCHITECTURE (all ratified, D-017); 5 WAVES amendment logs; every contract except T-05 amended after D-016/D-017 |
| Defects (C/H/M/L) | QA: 0/0/0/4 (D-01..D-04, all closed). Review: many round-1 Mediums (not itemised in the record) |
| Review rounds per branch | Most 2; T-05, T-06 and T-19 reached a scoped round 3 (the record names T-05 and T-19 explicitly, D-024 and D-029); T-06 is from the orchestrator notes. Exact average is unavailable |
| Gate failures | G3 failed twice (D-005, D-006). G4 was applied per wave (D-018). No G5/G6/G7/G8 failures. Within-wave failure: T-16 merge blocked (D-029); T-20 mistaken revert (D-027) |
| Discussions convened (cap 3) | 0 formal. Chair-by-fiat rulings were used (D-022, D-024, D-029) |
| New debt entries / expired unscheduled | 0 / 0. The workarounds were instead recorded in BACKLOG (23 items, 4 marked Required) and in D-022, so DEBT.md went unused |
| Tokens by tier | Only partial data at G4: about 1.4M for planning roles. Per-role spend for implementation and review was not recorded, so the spend analysis cannot be done |

## Root causes
| Class | Count | Examples |
|---|---|---|
| Contract ambiguity / contract gap | about 6 | Wave-0 stub-throw assertions blocked all Wave 1 (T-10 CONTRACT_ISSUE); §G rows 29-37 had no owner (R-13, D-025); `config.py` needed a `BIND_FAILED` code, so a frozen-file exception (D-032); SR-1 test (i) described a profile field that did not exist (WAVES, "New, minor") |
| Architecture gap | 10 | CI-1..CI-10 (D-017), found only when Tech Lead wrote contracts. Also D-016 (§6.8 not reconstructible from the token) |
| Engineer error | few | Mostly folded into test gaps |
| Test gap | dominant (majority of review Mediums) | "Passes for the wrong reason / mutant survives": T-05 (D-024), T-06 B-10, T-07 B-11, T-09 B-12, T-24 B-20, T-16 B-22/B-23; QA's NFR08 test expectation was wrong, not the code (QA triage) |
| Security design gap | 3 recurring | Lint-ban bypasses (T-01, D-019, then semgrep T-14); Fetcher boundary B-06 (T-10 and T-11, same class twice, §6 smell); T-19 decode-cost DoS |
| Tooling / process | 6 | Release Engineer stash (D-021); mistaken revert of expected-red tests (D-027); classifier blocking merges (D-027, D-029); shared scratchpad clashes (D-026 and one other); semgrep landing after T-16's review (R-11, D-028); QA near-miss overwriting approved `spec/vectors` (B-21, D-031) |

## What worked
- Verbatim normative text, ADRs and V-01 fact verification before Wave 1: no Wave-1 task needed a design reversal.
- Per-wave G4 with an explicit expected-red table (WAVES.md) made "red by design" auditable, and a D-025/D-032-style narrow frozen-file exception handled the later gaps cleanly.
- Independent reviewer re-implementations of codecs and vector cases (D-020, D-026, D-030), plus 100% line and branch coverage, gave strong evidence at G5 and G7.

## Recommendations (≤5)
| # | Change | File / section | Type | Because | Expected effect |
|---|---|---|---|---|---|
| 1 | Add a mandatory "Mutation self-check" section to the Task Report. For each acceptance criterion, name the one-line production change that would break it and state that it was reverted-and-rerun red. Wording: "For every criterion, list the production line you broke and the failing test name. DONE is invalid without this." Mirror it in the Code Reviewer checklist in place of ad hoc spot-checks. | `sdlc/templates/TASK_REPORT.md`; `sdlc/roles/software-engineer.md` (before reporting DONE) | template | Test-gap Mediums were the dominant review finding and caused T-05, T-06 and T-19 round 3 (D-024 follow-up, B-10, B-11, B-12, B-20) | Moves the survivor hunt from STRONG review rounds to MID authoring; fewer round-2/3 cycles |
| 2 | Add a "Frozen stubs" rule to the Wave-0 contract: stub files may pin signatures only, never assert the stub's own failure (no `NOT_IMPLEMENTED` tests). Add the checklist line "Every Wave-0 test must stay green after any later-wave implementation." Add a G4 line: "each frozen type has an owner for every enum member and catalogue row it may need". | `sdlc/templates/TASK_CONTRACT.md` ("Files owned"); `sdlc/roles/tech-lead.md` G4 checklist | template | Stub-throw assertions blocked every Wave-1 task (T-10 CONTRACT_ISSUE); R-13/§G rows and `BIND_FAILED` each needed a mid-increment frozen-file exception (D-025, D-032) | Fewer unplanned tasks; fewer frozen-file exceptions |
| 3 | Replace the Release Engineer prompt's judgement step with a scripted merge gate: the Orchestrator supplies REQUIRED and EXPECTED-RED command lists, and the agent only runs them and reports exit codes. Forbid stash, revert and reset. Keep the tier FAST. Add a permission rule for `git merge --no-ff inc-*/*` so merges do not need the human (human decision). | `sdlc/roles/release-engineer.md`; `.claude/settings.json` permission rules (human) | role-prompt | The stash (D-021), the mistaken revert (D-027) and classifier blocks (D-027, D-029) each needed human or Orchestrator rescue | Removes a recurring human interruption and a destructive-action risk |
| 4 | Make the Tech Lead's architecture-conformance pass a pre-G4 requirement: for each boundary, draft the type or contract test against ARCHITECTURE.md before G2 closes. Add to the Architect prompt: "Every interface in the document must be accompanied by its concrete TypeScript or Python signature, error enumeration and one example call." Set the G2 check to fail on prose-only interfaces. | `sdlc/roles/architect.md` (Outputs); `sdlc/core/PROCESS.md` §3.2 G2 text | design | CI-1..CI-10 were ten Wave-0 type gaps found only at G4 (D-017); plus D-016 and ADR 0009/0010 were late | Pushes interface defects to G2, where the Architect fixes them cheaply |
| 5 | Make per-role token logging and review-round counts a required column in STATUS.md's gate update, and wire "toolchain-in-lint_command" as a G4 condition: any scanner or semgrep rule landing in a wave must be in `lint_command` in the same merge. Replace unused DEBT.md entries with a pointer rule: BACKLOG items marked Required must be copied to the next INCREMENTS.md at G4. | `sdlc/templates/docs/STATUS.md` (Spend table); `sdlc/core/PROCESS.md` §3.4 G4; `sdlc/roles/orchestrator.md` | process (sharpening) | Spend and review rounds could not be reconstructed for this retro; R-11 (semgrep outside lint_command) delayed a merge; B-05/06/08/13 depend on someone remembering | Makes the next retro measurable; stops required follow-ups being lost |

Note on #5: it adds a record, not a step. If the Orchestrator rejects it, #1 to #4 stand independently.

## Confidence
- Test-gap dominance rests on one increment but on many events (≥8 findings); treat as a pattern.
- The FAST Release Engineer failure is two events (D-021, D-027); the classifier blocking is two (D-027, D-029). Watch, but the scripted gate is cheap.
- Architecture-gap count (CI-1..CI-10) may be inflated by this being INC-1 and the first Tech Lead pass; recommendation #4 should be re-evaluated after INC-2.
- Spend, review-round averages and the exact review finding counts are not in the supplied inputs. Numbers marked "about" are inferred from DECISIONS.md and WAVES.md.
- The shared-scratchpad clashes (two events) are not given a recommendation; the existing D-026 rule (task-specific scratch subdirectories) already covers them. Check it in INC-2.
