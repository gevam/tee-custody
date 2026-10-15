# Retrospective — INC-2

Date: 2026-10-15   Tag: inc-2 (local, 0e20909)   Author: retrospective-analyst

## By the numbers
| Metric | Value |
|---|---|
| Tasks / waves | 44 items (T-01..T-42, V-01, V-02) in 6 waves, plus 7 QA branches and 2 merge units (MU-1, MU-2). Planned 38 items; T-38..T-42 were added mid-increment (D-02, B-45, D-03..D-07). Growth about 16%, below the 30% trigger |
| CONTRACT_ISSUE returns / contract amendments | Few formal CONTRACT_ISSUEs (one DESIGN_ISSUE: T-40 contract inputs, D-072). About 70 amendments (counted as the highest A-index per file; approximate) across 30 of 42 task files. Highest: T-27 A1..A8, T-31 A1..A6, T-40 A1..A6, T-26 A4 |
| Defects (C/H/M/L) | QA/review-filed D-01..D-07: 0/0/5/2 (Medium D-01, D-02, D-03, D-05, D-07; Low D-04, D-06). All closed. Review round-1 findings include at least 5 Highs (T-12, T-14, T-26, T-33, T-35), not itemised in the record |
| Review rounds per branch | Most 2. Past `review.max_rounds`: T-21 (A2), T-26, T-29 (A2), T-31 (A6), T-40 (A6), plus T-27 round 3. About 6 of 38 reviewed branches. Exact average unavailable |
| Gate failures | None recorded at G5, G6, G7, G8. Within-wave: MU-2 could not merge alone (D-062); trunk went red after QA-I7 (fb8f608); G6 held for T-39..T-42 |
| Discussions convened (cap 3) | 0 formal again. Rulings were Tech Lead amendments (D-053) and Architect decisions |
| New debt / expired unscheduled | DEBT-2, DEBT-3 (both expire INC-5). 0 expired. BACKLOG grew to B-52; 7 are Required for INC-3 |
| Spend | Not recorded. STATUS.md still has only the INC-1 table. INC-1 recommendation 5 (spend column) did not take effect |

## INC-1 recommendations: applied?
| # | State | Evidence |
|---|---|---|
| 1 Mutation self-check | Applied (TASK_REPORT, software-engineer, code-reviewer). Partly effective | T-38 and T-42: all mutants killed. Reviewers still found survivors: T-35 (3 mutants), T-39 (untested guard), T-41 (seal-rollback nonce reuse survived the Core suite), QA-I7. Self-mutation misses option-parsing and refuse paths |
| 2 Frozen stubs | Applied (TASK_CONTRACT line 17, tech-lead item 7). Worked | No stub-throw CONTRACT_ISSUE recurred |
| 3 Scripted release gate | Not verifiable | Release Engineer correctly refused T-25 without a recorded verdict; the supplied gitleaks command was wrong (`--no-git`) |
| 4 Interfaces with signatures and errors (G2) | Applied (architect.md), insufficient | Error codes still added outside frozen contracts: T-10, T-23, T-24, T-26. D-04 and D-07 are boundary gaps |
| 5 Spend column / G4 lint rule | G4 text applied; spend not | No INC-2 spend data |

## Root causes
| Class | Count | Examples |
|---|---|---|
| Contract ambiguity / gap | about 12 | Error codes outside contracts (4 tasks); T-40 inputs never run against h11 (D-072); T-19 `baseUrl`; D-01 acceptance tests over-asserted |
| Architecture gap | 2 | D-07 (full page 1.4 MB vs 1 MiB client limit); D-04 (parse failures outside the JSON contract) |
| Security design gap | 5, one dominant class | D-03, D-05, D-06 are the gateway connection-lifecycle class, found in three separate stages; T-12 flood eviction; T-29 `expires_at` across a blocking pull |
| Engineer error | 4 fix-introduced regressions | T-33 (High), T-26, T-29 CM1 (missed by SR), T-31 (Medium, `detached: true`) |
| Reviewer error | 3 | T-21 (Low asked to drop a defects check), T-32 (mutant edited a comment; High retracted), T-33 (SR dismissed a real High) |
| Test gap | dominant | Wrong-kind rejections (T-07, T-15); T-35, T-39, T-41, QA-I7 survivors; T-21 deleted 3 tests unflagged |
| Tooling / environment | 8 | WSL2 clock steps (D-02, ADR 0013); 20-agent subagent cap queued reviews; scratch collisions (T-23; T-30 dir outside scratch); `pnpm -r test` bail hid packages; gitleaks misrun or skipped on test-only branches; Playwright 1.64 vs lock 1.63; stale `tc-e2e-*` dirs; wrong commit trailer on 4eaa77a |

Late catches: T-29 CM1 and the T-31 Medium reached the final round; D-03, D-05, D-06 and D-07 surfaced at QA or T-40 review, after the work looked complete. D-02's cause was an INC-1 contract choice (zero-leeway nbf) that overrode an SA non-blocking note.

## What worked
- Mutation-based review: T-33, T-39, T-41 and QA-I7 gaps were found by reverting and rerunning.
- All seven defects closed in-increment with a named task; none deferred to the human.
- The verdict-before-merge refusal and merge units MU-1/MU-2 kept trunk consistent.
- Root-causing D-02 to the clock before changing product code, then ADR 0013.

## Recommendations (≤5)
| # | Change | File / section | Type | Because | Expected effect |
|---|---|---|---|---|---|
| 1 | Add to "Interface contract": "Error table: for every function, list every error code it may return or raise, with its trigger. A code not in the table is not allowed; if you need one, return CONTRACT_ISSUE." Add the same line to `software-engineer.md` under CONTRACT_ISSUE, and a Tech Lead G4 item: "every function in the contract has an error table". | `sdlc/templates/TASK_CONTRACT.md` ("Interface contract"); `sdlc/roles/software-engineer.md`; `sdlc/roles/tech-lead.md` | template | T-10, T-23, T-24, T-26 each added codes; D-053 and D-056 asked for this | Removes a recurring amendment class |
| 2 | Add a "Fix-round checklist" to both reviewers: "For each fix since the last round: (a) state what the previous behaviour covered that the fix removes; (b) rerun the hostile-input set for the touched function (wrong type, zero, NaN, aborted run, Ctrl-C); (c) list any deleted or moved test and approve or reject it by name; (d) a finding that rests on a mutant shows the mutant diff and the failing and passing output; (e) never dismiss a fail-open as caller misuse." | `sdlc/roles/code-reviewer.md`, `sdlc/roles/security-reviewer.md` (Procedure) | role-prompt | 4 fix-introduced regressions; 3 reviewer errors; T-21 deleted tests | Fewer final rounds and retracted findings |
| 3 | Add a Contract section "Time, process and resource cases": "If the task has a deadline, expiry or skew, tests advance the clock inside every blocking port call. If it spawns a process, name runner-death, SIGINT and SIGKILL cases and the cleanup assertion. Every test that runs a loop has a tick budget. Test inputs quoted in the contract are run against the real dependency in the Tech Lead's prototype." | `sdlc/templates/TASK_CONTRACT.md`; `sdlc/roles/tech-lead.md` (checklist item 8) | template | T-29 CM1 and SL1 (hang), T-31 orphan, T-40 DESIGN_ISSUE, D-03/D-05/D-06 same class in three stages | Moves lifecycle defects from the last review round to authoring |
| 4 | Change `test_command` to use `pnpm -r --no-bail test`. In `release-engineer.md` replace the secret-scan step with `gitleaks detect --log-opts=<base>..<tip>` (never `--no-git`), run for every branch including test-only ones before its verdict is recorded. In `orchestrator.md`: "Record each task's final verdicts in DECISIONS.md before dispatching its merge." Add `packages/teecustody-web/test-results/` to `.gitignore`. | `framework.yaml` (`test_command`); `sdlc/roles/release-engineer.md`; `sdlc/roles/orchestrator.md`; `.gitignore` | config | Bail hid packages and left T-35 without a web baseline; QA-I7 turned trunk red (fb8f608); D-056 back-fill | Removes red-trunk and missing-baseline events |
| 5 | Add to the engineer and reviewer spawn rules: "Scratch root is `<scratchpad>/<task>-<role>/`, created by the Orchestrator and passed in the prompt; never write elsewhere. Run gitleaks before each commit. Do not rewrite branch history; if you did, say so in the Task Report." | `sdlc/roles/software-engineer.md` (Rules); `sdlc/roles/orchestrator.md` (spawn prompt) | role-prompt | Scratch collisions in INC-1 and INC-2 (T-23, T-30): the D-026 rule did not hold; T-40 rewrote history | The same defect class in two increments (§8) is closed by an assigned path, not a rule |

## Confidence
- Defect counts are small (7); the connection-lifecycle class (D-03/D-05/D-06) rests on three events in one component. Treat as a design smell to check in INC-3's custody and KMS code, not a certainty.
- Amendment counts are a heuristic from A-numbers in task files; review-finding counts and spend are not in the record (second increment running).
- Fix-introduced regressions (4) and reviewer errors (3) rest on few events; recommendation 2 is a checklist, so it is cheap to drop.
- Not recommended: SA "non-blocking notes" becoming BACKLOG items (D-02, one event); the Orchestrator already does this, so watch only.
