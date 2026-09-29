# SDLC Framework — Core Process

This document defines *how the team works*. It is project-agnostic. Everything project-specific lives in `framework.yaml` (tiers, thresholds, budgets) and in the artifacts the team produces under `docs/`. Role behaviour lives in `roles/*.md`. Templates live in `templates/`.

The **Orchestrator** (roles/orchestrator.md) executes this process. Every other role is invoked by the Orchestrator with its role prompt plus only the artifacts that role needs.

---

## 0. Operating principles

1. **MVP in stages.** Every project is delivered as a sequence of increments. Increment 1 is the thinnest vertical slice that proves the architecture end to end. Later increments add capability. Never build everything before anything works.
2. **Design is the source of truth.** `docs/ARCHITECTURE.md` and its ADRs are living documents. When implementation reveals a problem, the question is always *"is the design wrong, or is the code wrong?"* — code quality signals route back to design, not to local patches.
3. **Security by design.** Threat modeling happens before code. Security review happens after architecture and again before every merge. Security findings are defects, not suggestions.
4. **Right-sized intelligence.** Product/PM judgment uses VERY STRONG models; planners and reviewers use STRONG; workers use MID; mechanical tasks use FAST. Strong models produce specs precise enough that weaker models cannot misinterpret them. Token budget is a design constraint.
5. **Parallel by default, serial by necessity.** Work is decomposed so independent tasks run concurrently. Dependencies are explicit; shared files are owned by one task at a time.
6. **Humans decide the big things.** The Orchestrator escalates when implications are large (§8). It never silently absorbs a scope, security, or architecture change.
7. **Evidence over assertion.** "Done" means tests pass, reviews are approved, and the merge is clean — shown, not claimed.
8. **TDD is mandatory, not stylistic.** No production code is written without a failing test that demands it. Acceptance criteria become tests before a task starts; engineers work red → green → refactor; reviewers verify test-first evidence and reject code that arrived before its tests (§7a).
9. **Discussion is bounded.** Agents may confer when a decision needs more than one perspective, but every discussion has a question, a chair, a round limit, and a tie-breaker (§11). No debate runs open-ended.

---

## 1. Model tiers

Tiers are abstract. `framework.yaml → tiers` maps each tier to a concrete model for the project; the Orchestrator copies that mapping into `docs/TEAM.md` at project start so it is visible in the repo.

| Tier | Purpose |
|---|---|
| VERY_STRONG | Product management: intake, requirements, scope, prioritization, increment ordering, gate decisions, human escalation, chairing discussions |
| STRONG | Architecture, threat modeling, task decomposition, code review, security review, conflict resolution |
| MID | Implementation, unit/integration tests, QA test authoring, documentation |
| FAST | Formatting, lint fixes, changelog, status summaries, mechanical refactors from an exact spec |

Rule: **a task's tier is set by the cost of getting it wrong, not by its size.** A ten-line auth check is STRONG-reviewed. A 500-line CRUD scaffold from a precise spec is MID. PM work is VERY_STRONG because a wrong requirement or a wrong increment order is the most expensive mistake in the pipeline — every downstream token is spent on it.

VERY_STRONG is used sparingly: at gates, at intake, and to chair or break ties in discussions. It is never used for volume work.

---

## 2. Team roles

| Role | Tier | Owns | Produces | Prompt |
|---|---|---|---|---|
| Orchestrator / PM | VERY_STRONG | Product judgment, scope, prioritization, stage gates, delegation, escalation, task graph, chairing discussions | `docs/STATUS.md`, `docs/DECISIONS.md` | roles/orchestrator.md |
| Product Analyst | VERY_STRONG | Intake: unambiguous requirements, acceptance criteria, increment ordering | `docs/REQUIREMENTS.md` | roles/product-analyst.md |
| Architect | STRONG | System design, boundaries, interfaces, data model, tech choices, increment plan | `docs/ARCHITECTURE.md`, `docs/adr/*.md`, `docs/INCREMENTS.md` | roles/architect.md |
| Security Architect | STRONG | Threat model, trust boundaries, security requirements, design security review | `docs/THREAT_MODEL.md`, security ADRs | roles/security-architect.md |
| Tech Lead | STRONG | Decomposes an increment into parallel-safe tasks with contracts and file ownership | `docs/tasks/INC-N/*.md`, dependency graph | roles/tech-lead.md |
| Software Engineer (N in parallel) | MID | One task: TDD implementation on its own branch/worktree | Code + tests + Task Report | roles/software-engineer.md |
| QA Engineer | MID | Acceptance/integration tests from requirements, independent of engineers' tests; exploratory testing | `tests/acceptance/*`, `docs/qa/INC-N.md` | roles/qa-engineer.md |
| Code Reviewer | STRONG | Correctness, design conformance, maintainability, TDD evidence | Review verdict per branch | roles/code-reviewer.md |
| Security Reviewer | STRONG | Vulnerabilities, secrets, dependency risk, threat-model conformance | Security verdict per branch | roles/security-reviewer.md |
| Release Engineer | FAST | Rebase, merge, changelog, tag, CI status | Merged trunk | roles/release-engineer.md |
| Retrospective Analyst | MID | What broke, what to change for next increment | `docs/retro/INC-N.md` | roles/retrospective-analyst.md |

Roles are hats, not headcount. Never let one agent review its own work.

---

## 3. Pipeline

Stages 3.1–3.3 run once per project; 3.4–3.9 run per increment. Every stage ends with a **gate** the Orchestrator checks before proceeding.

### 3.1 Intake (Product Analyst)
- Read the project definition (`PROJECT.md`, templates/PROJECT.md). List every ambiguity, missing constraint, and implicit assumption.
- Resolve what can be resolved by reasonable default; **ask the human** for anything that changes scope, cost, users, or data handling (§8).
- Capture non-functional requirements explicitly: performance, availability, i18n/RTL, accessibility, compliance, deployment target, budget.
- Output `docs/REQUIREMENTS.md`: numbered FR-n and NFR-n, each with testable acceptance criteria, plus an explicit **Out of Scope** section.

**Gate G1:** Every requirement has an acceptance criterion. Human has answered blocking questions. No "TBD" in scope.

### 3.2 Architecture (Architect)
- Produce `docs/ARCHITECTURE.md`: context, component boundaries, layering (hexagonal/ports-and-adapters or equivalent), data model, integrations, error handling, observability, deployment shape.
- One ADR per significant decision (`docs/adr/NNNN-title.md`).
- Produce `docs/INCREMENTS.md`: ordered increments, each a shippable vertical slice with its own acceptance criteria. Increment 1 exercises every architectural layer at least once.
- Define **interface contracts** at every boundary that will be split across engineers (types, schemas, signatures, error semantics).
- Choose the test strategy: unit / integration / acceptance layers, fixtures, test data policy.

**Gate G2:** Architecture traces to every FR/NFR. Every cross-component boundary has a written contract. Increment 1 is small enough to complete in one pass.

### 3.3 Security architecture review (Security Architect)
- Build `docs/THREAT_MODEL.md` (STRIDE or equivalent): assets, actors, trust boundaries, entry points, threats, mitigations, residual risk.
- Review `ARCHITECTURE.md` against it. Produce **security requirements** (SR-n) with acceptance criteria and a test description for each.
- Verdict: APPROVE / CHANGES_REQUIRED. Changes go back to the Architect; loop until approved.

**Gate G3:** Threat model exists; every High/Critical threat has a mitigation in the design; SR-n are in `REQUIREMENTS.md` with test descriptions; human has been shown residual risks and accepted them.

### 3.4 Work breakdown (Tech Lead) — per increment
- Decompose the increment into tasks, one file each (`docs/tasks/INC-N/T-nn.md`) using the **Task Contract** (templates/TASK_CONTRACT.md).
- Build the dependency graph. Maximize tasks per parallel wave. Foundation tasks (schema, shared types, interface stubs, contract tests) are Wave 0.
- Assign **file ownership**: every file in the increment belongs to exactly one task per wave. Cross-cutting changes are their own earlier-wave task.
- Assign a tier to each task.

**Gate G4:** No two tasks in the same wave touch the same file. Every task's inputs are outputs of earlier waves or existing code. Every task's acceptance tests exist as executable tests that currently **fail** on trunk. Every boundary in the wave has a contract test stub.

### 3.5 Parallel implementation (Software Engineers)
For each wave, spawn one engineer per task concurrently. Each engineer works on `inc-N/T-nn-slug`, reads only its contract and the contracts it touches, works strictly TDD (§7a), runs the full suite and linters, and returns a **Task Report** (templates/TASK_REPORT.md). If blocked or the contract is wrong: stop and report. Never widen scope or change an interface silently.

**Gate G5:** All tasks report DONE with green tests. Coverage on new code ≥ `framework.yaml → coverage.line_min`; 100% on security-relevant paths.

### 3.6 QA (QA Engineer)
- Authoring runs in parallel with 3.5 after Wave 0: acceptance/integration tests derived from `REQUIREMENTS.md` and `INCREMENTS.md` **without reading engineers' tests**.
- After G5: execute against the integrated increment branch; exploratory testing on error paths, edge inputs, concurrency, every threat-model entry point.
- Defects filed as `docs/tasks/INC-N/D-nn.md` with reproduction steps and severity.

**Gate G6:** All acceptance criteria for the increment pass. No open Critical/High defects. Medium/Low triaged: fix now or explicitly deferred with human sign-off.

### 3.7 Review (Code Reviewer + Security Reviewer, in parallel)
Per task branch (or increment branch if tasks are small). Verdicts: APPROVE / REQUEST_CHANGES / DESIGN_ISSUE, findings severity-tagged.

Routing:
- REQUEST_CHANGES → same engineer. Max `review.max_rounds` rounds, then Tech Lead.
- Engineer disputes a finding → one bounded discussion (§11), chaired by Tech Lead.
- DESIGN_ISSUE → Architect (§6). Branch frozen until resolved.
- Any Critical security finding → blocks the entire increment merge.

**Gate G7:** Both reviewers APPROVE every branch. Zero Critical/High security findings.

### 3.8 Merge (Release Engineer)
- Rebase each branch on trunk in dependency order, full suite after each rebase, merge with a conventional commit referencing the task ID.
- Update `CHANGELOG.md`, tag `inc-N`.
- Non-mechanical conflicts → owning engineer; overlapping ownership noted for the retro.

**Gate G8:** Trunk is green, tagged, and deployable per `ARCHITECTURE.md`.

### 3.9 Retrospective (Retrospective Analyst)
- Defects by root cause, review findings by category, contract ambiguities, wasted tokens, blocked time, discussions convened.
- Recommend changes to design, templates, or role prompts. Orchestrator applies accepted changes before the next 3.4.

---

## 4. Task Contract
See templates/TASK_CONTRACT.md. A STRONG model writes it; a MID model must complete it without asking. If a worker has to ask, the contract was deficient — fix the template, not just the task.

## 5. Task Report
See templates/TASK_REPORT.md. ≤200 words. The Orchestrator never receives worker transcripts.

---

## 6. Refactor vs. workaround

| Signal | Default | Who decides |
|---|---|---|
| Local to one task, no contract touched | Fix in place | Engineer |
| Contract change affecting ≤1 other task in this increment | Amend contract, update both tasks | Tech Lead |
| Contract change affecting >1 task, or data model change | Architect evaluates refactor vs. workaround; Architect/Tech Lead disagreement → §11 | Architect → Orchestrator |
| Same class of problem in ≥2 tasks | Design smell — refactor, don't patch twice | Architect |
| Would violate an ADR or the threat model | Refactor or new ADR; never a silent workaround. Architect + Security Architect confer (§11) first | → **human** |
| Workaround chosen | Record in `docs/DEBT.md` with an expiry increment | Orchestrator |

A workaround is acceptable only if it is (a) invisible outside its module, (b) recorded, and (c) scheduled for removal. Workarounds on security controls are never acceptable.

---

## 7. Parallelism rules

- One task, one branch/worktree, one owner. No shared working directories.
- Shared code (types, schemas, migrations, config) changes only in a dedicated earlier-wave task.
- Contracts freeze once a wave starts. Changing one mid-wave pauses every dependent task.
- Waves merge in order; a wave never starts on an unmerged base unless proven independent of the pending merge.
- Concurrency is capped at the number of truly independent tasks and by `framework.yaml → parallelism.max_engineers`.
- QA authoring runs in parallel with implementation; QA execution runs after integration.

---

## 7a. TDD discipline (enforced)

| Layer | Who writes tests first | Enforced at |
|---|---|---|
| Acceptance (Given/When/Then per FR) | Product Analyst writes criteria; QA makes them executable | G4: task cannot start until its acceptance tests exist and **fail** on trunk |
| Integration (contracts) | Tech Lead ships contract tests with every interface contract | G4: contract test stubs for every boundary in the wave |
| Unit | Software Engineer | G5 + Code Review: test-first evidence in commit history |
| Security (each SR-n) | Security Architect specifies; QA/Engineer implement | G3: every SR-n has a test description; G7: it passes |

**Engineer cycle (non-negotiable):**
1. Write one failing test from the next acceptance criterion. Run it. **Confirm it fails for the right reason** — record the failure message.
2. Write the minimum code to make it pass. Run the full suite.
3. Refactor with the suite green. Commit.
4. Repeat until every criterion has a test. Only then handle edge cases the criteria didn't name — also test-first.

**Commit convention:** tests and the code they drive are committed together, or the test commit precedes the implementation commit. Production code with no corresponding test change is a High review finding unless it is a pure refactor.

**Reviewer verification:** spot-check `review.tdd_spot_checks` tests by reverting the implementation and confirming they fail. Reject: tests that mirror implementation; after-the-fact happy-path tests; assertion-free coverage; skipped/xfail tests without a linked defect.

**When TDD is hard** (UI, infra, exploration): a declared, time-boxed **spike** on a throwaway branch, then delete and re-implement test-first. Spike code is never merged.

**Coverage is a floor, not a goal.** Reviewers judge the tests, not the number.

---

## 8. Human escalation

Stop and ask the human — concise summary, options, recommendation — when:

- **Scope:** ambiguity that changes the product; increment effort grows > `escalation.effort_growth_pct`.
- **Architecture:** changing a public API, data model, storage engine, framework, or deployment shape after G2.
- **Security:** accepting any High/Critical residual risk; a dependency with restrictive license or no maintenance; any authn/authz model change; personal or regulated data not in the original definition.
- **Cost:** projected spend exceeds `budget` in `framework.yaml`.
- **Repeated failure:** a task fails review `escalation.max_review_failures` times; the same defect class recurs across two increments.
- **Irreversibility:** destructive migrations, deleting data, force-pushes, external side effects (payments, emails, third-party writes).

Never escalate for things decidable with a documented default. Batch non-blocking questions; interrupt only for blocking ones.

---

## 9. Repository layout the team maintains

```
PROJECT.md                              ← human-written input (templates/PROJECT.md)
framework.yaml                          ← project config (templates/framework.yaml)
docs/
  REQUIREMENTS.md  ARCHITECTURE.md  THREAT_MODEL.md  INCREMENTS.md
  TEAM.md          DEBT.md          STATUS.md        DECISIONS.md
  adr/NNNN-*.md    tasks/INC-N/T-nn.md, D-nn.md      qa/INC-N.md    retro/INC-N.md
src/   tests/unit/   tests/integration/   tests/acceptance/
CHANGELOG.md
```

`STATUS.md` is rewritten at every gate: stage, wave, tasks by state, blockers, open human questions, spend to date.

---

## 10. Context each role receives

| Role | Receives |
|---|---|
| Product Analyst | PROJECT.md, framework.yaml |
| Architect | REQUIREMENTS.md, framework.yaml (stack constraints) |
| Security Architect | ARCHITECTURE.md, REQUIREMENTS.md, adr/ |
| Tech Lead | ARCHITECTURE.md, INCREMENTS.md (current increment), THREAT_MODEL.md (SR-n), adr/, templates/TASK_CONTRACT.md |
| Software Engineer | Its T-nn.md, the contracts it touches, the referenced ARCHITECTURE.md section, coding standards from framework.yaml |
| QA Engineer | REQUIREMENTS.md, INCREMENTS.md, THREAT_MODEL.md entry points. **Not** engineers' tests |
| Code Reviewer | The diff, T-nn.md, ARCHITECTURE.md, adr/ |
| Security Reviewer | The diff, THREAT_MODEL.md, REQUIREMENTS.md (SR-n) |
| Release Engineer | Branch list with dependency order, CHANGELOG.md |
| Retrospective Analyst | STATUS.md history, DECISIONS.md, defects, review findings, DEBT.md |

Nothing else. Narrow context is both a cost control and a correctness control.

---

## 11. Bounded discussion protocol

Agents do not chat. When a decision needs more than one perspective, the owning role **convenes a discussion** with the structure below. Anything that doesn't fit is decided unilaterally by the owning role per §6.

**Allowed when:** two roles hold conflicting positions on a blocking decision; a gate has failed twice for reasons pointing in different directions; the Architect requests one design critique before G2.
**Not allowed:** brainstorming, alignment, status syncs, anything without a single decidable question.

```
Question:      one sentence, answerable with a choice or yes/no
Participants:  2–3 roles
Chair:         the role that owns the decision per §6; ties → Orchestrator
Round limit:   discussion.default_rounds (max discussion.max_rounds)
Word budget:   discussion.words_per_round per participant per round
Inputs:        the artifacts participants may cite — no new research mid-discussion
```

- **Round 1 — Positions.** Position, top 3 reasons, what evidence would change their mind. Written in parallel, blind to each other.
- **Round 2 — Response.** Concessions, remaining disputes and why, final recommendation. New arguments allowed; new topics not.
- **Round 3 (chair opens only if needed).** One narrowed question; ≤ half the word budget each.
- **Close.** Chair decides and writes a Decision Record (templates/DECISION_RECORD.md) to `DECISIONS.md`.

**Hard limits:** ends at the round limit regardless of consensus — "no decision" is not permitted; chair who cannot decide escalates a summary to the Orchestrator, who decides in one pass (or to the human if §8 applies); a decided question is not reopened in the same increment without new evidence; at most `discussion.max_per_increment` discussions per increment — hitting the cap is logged for the retro; overflow beyond the word budget is ignored.

**Cost rule:** a discussion costs ≈ participants × rounds × word budget. If reversal cost is low, decide unilaterally, record, move on.

---

## 12. Orchestrator loop

```
read PROJECT.md + framework.yaml → write docs/TEAM.md
intake → G1 → architecture → G2 → security architecture review → G3
for each increment in INCREMENTS.md:
    work breakdown → G4
    for each wave: engineers in parallel; QA authoring after wave 0
    G5 → QA execution → G6 → code + security review (parallel) → G7 → merge → G8
    retrospective → apply accepted changes
    rewrite STATUS.md → report to human
```

On any gate failure: route to the owning role (§6), record in `DECISIONS.md`, re-check. If two roles conflict, convene one discussion (§11) first. Three consecutive failures of the same gate → human (§8).
