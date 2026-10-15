# INC-2 Orchestrator retro notes (input to docs/retro/INC-2.md)

Collected by the Orchestrator during INC-2 (2026-10-11..15). These are raw observations; the Retrospective Analyst decides what to recommend.

- RETRO: T-33 round-1 Low fix (new Uint8Array) introduced a High (numeric nonce → zeros); SR round 2 saw and dismissed it; CR caught. Lesson: reviewer recommended fixes need the same hostile-input tests; "caller misuse" is not a dismissal for fail-open.
- RETRO: T-21 round-1 CR Low was wrong (drop defects check) → reopened §16.3; needed extra round via TL (reviewer error).
- RETRO: T-21 removed 3 malformed-state test cases + moved OPTIONS 405 cases (intentional per comments) — reviewers approved; check deletions get explicit review attention.
- RETRO: scratchpad collisions recurred (T-23 wrote into another agent's mut.JPfI). Fix for INC-3: per-agent scratch root assigned in the prompt (e.g. scratchpad/<task>-<role>/), never shared pointers.
- RETRO: engineers repeatedly add error codes not in frozen contracts (T-10 TIMESTAMP_RANGE, T-23 SESSION_LIMITS/SESSION_ID_IN_USE) — contract template should enumerate error codes per function; engineers must return CONTRACT_ISSUE instead.
- RETRO: Orchestrator should record each task's final verdicts in DECISIONS before dispatching a merge (Release Engineer rightly refused T-25 without a recorded verdict; D-056 back-filled Wave 2).
- Retro: T-29 round 2 reached the limit. CR found that a pull blocking across expires_at still gets processed. SR's round-2 PoC missed this, because its clock did not advance inside pull. TL A2 approved a final round (d2c3f29). Lesson: time-bound controls need tests with a clock that advances inside every blocking port call.
- Retro: SL1. Reverting a control hung the suite instead of failing it. Tests that call run() need a tick budget.
- Retro: `pnpm -r test` bails at the first failing package, so a red package hides the others and leaves them without a baseline. The T-35 release had no baseline for web. Recommend `--no-bail` in test_command or in the release baselines.
- Retro: the T-35 round-1 CR found 3 surviving mutants: unknown options with a value, argv[0], and a fail-open catch. Engineer self-mutation missed option-parsing paths.
- Retro: T-31 round 2's fix (`detached: true`) introduced a Medium: Ctrl-C now orphans the harness and its FIXTURE_CS. This is the 4th fix-introduced regression (T-33, T-26, T-29 CM1 was missed, T-31). Recommend: a reviewer checklist item, "for each round-N fix, ask what the previous behaviour covered that the fix removes".
- Retro: process-lifecycle tests (signals, groups, runner death) keep surfacing late. The contract template should name runner-death and Ctrl-C cases for any task that spawns processes.
- Retro: D-02. A zero-leeway nbf (an Orchestrator contract choice in INC-1 T-12) overrode an SA non-blocking note. Lesson: an SA "non-blocking note" on a security check must become a BACKLOG item, not get lost. A WSL2 clock-stepping host exposed it. ADR 0013 is the fix, T-38.
- Retro: release prompts must give the exact gitleaks command (`gitleaks detect --log-opts=HEAD`). The QA-T-38 release used --no-git and stopped on a PEM-header literal in sim/tests/test_keys.py:214.
- Retro: a stale /tmp/tc-e2e-udporbjr (fixture share) was left by a SIGKILLed run, probably a reviewer's mutation run. Deleted 18:28. Consider a CI step and global-setup that sweeps stale tc-e2e-* dirs whose owner pid is dead.
- Retro/G6: V-02 FACTS were recorded with Playwright 1.64.0 (Firefox 157), but the lock pins 1.63.0 (Firefox 155). T-32 CR found Firefox 155 never requests favicon. FACTS must be re-checked at the locked versions before G6, or the lock bumped. Owner: QA/V-02.
- Retro: test-only QA branches skipped the security review, so gitleaks never ran before merge. QA-I7 merged a JWT-shaped literal and turned the trunk gate red (fb8f608). Rule: every branch, test-only included, runs gitleaks --log-opts=<range> before its verdict is recorded.
- Retro: T-32 round-1 CR High was a reviewer error: the mutant edited a comment in serve.mjs, not the CSP line. Retracted in round 2. That made two reviewer errors this increment (T-21, T-32). Recommend: reviewers show the mutant diff, and the failing/passing output, in the finding.
- Retro: packages/teecustody-web/test-results/ (Playwright .last-run.json) is not gitignored and gets left untracked after browser runs. Add it to .gitignore (owner: T-32 follow-up / B-46).
- Retro: the T-40 contract inputs (a 20 KB header, 3000 headers) were never checked against h11's behaviour on complete requests. The TL prototype tested other inputs. The CR caught it via QA's verbatim rows. Lesson: contract test inputs must be validated in the prototype.
- Retro: the T-40 engineer rewrote its unpushed branch history with cherry-picks to drop a gitleaks-flagged RFC 6455 sample key. The tree is unchanged, and reviewers check that the TDD order survived. Recommend: an engineer contract rule. Run gitleaks before each commit, and never rewrite history without reporting it.

## Earlier INC-2 observations (Waves 0–2, from the Orchestrator's running log)
- Wrong-kind test gap in both T-07 and T-15: tests asserted rejection but not the specific error kind.
- Scratchpad collisions: engineers and reviewers repeatedly shared the scratchpad root. Fixed by mandating a per-agent `mktemp -d`.
- The T-04 engineer ran `git checkout` in a shared tree, which is forbidden. The Release Engineer rules were tightened: no stash, reset, `checkout -- .`, clean or `add -A`.
- Commit 4eaa77a carried a Haiku attribution trailer instead of the configured one.
- QA defects were found by engineers rather than by QA.
- Recurring `Buffer.slice` aliasing: views shared memory with caller buffers. This led to copy-on-read keys (§7.1/§7.2).
- T-19 `baseUrl` mismatch between the contract and the gateway paths.
- The harness's 20 concurrent subagent cap forced queueing of reviews.
- T-33 High (a numeric nonce became zero bytes) was introduced by a round-1 fix. The pattern repeated in T-26, T-31 and T-29 (fix-introduced regressions).
- T-21 reviewer error: a round-1 Low asked to drop a defects check. The Tech Lead approved a final round to restore it. T-32 had a second reviewer error: a mutant edited a comment, not the CSP.
- Engineers added error codes outside frozen contracts (the D-053 precedent: a Tech Lead amendment is required).
- T-21 deleted tests in a fix round.
- Merges were dispatched before verdicts were recorded in DECISIONS. The Release Engineer now refuses without a record.
- QA-7 missed a contract test.
- T-30 created a scratch dir outside the scratchpad (/home/geva/code/tmp/T-30-*). It is still present, pending human OK to delete.
