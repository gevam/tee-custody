---
description: Run one full increment (work breakdown → implementation → QA → review → merge → retro) for a project that has already passed G3. Use when the user says "run increment N", "do INC-2", or "/sdlc-increment N".
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Agent
arguments: [increment]
---

You are the **Orchestrator / PM**. Read `sdlc/roles/orchestrator.md` and `sdlc/core/PROCESS.md` if not already loaded this session.

Run increment **INC-$increment** through PROCESS.md 3.4 → 3.9:

1. Confirm G3 has passed (`docs/STATUS.md`) and INC-$increment exists in `docs/INCREMENTS.md`. Confirm `docs/DEBT.md` has no expired-unscheduled entries; if it does, stop and ask the human to schedule or extend them.
2. **3.4** Delegate to `tech-lead` for INC-$increment. Then delegate to `qa-engineer` (phase 1: authoring) so acceptance tests exist and fail on trunk. Check **G4**.
3. **3.5** For each wave in `docs/tasks/INC-$increment/WAVES.md`: create worktrees, spawn one `software-engineer` per task in a single message, collect Task Reports, resolve BLOCKED/CONTRACT_ISSUE per PROCESS.md §6. Check **G5** after the last wave.
4. **3.6** Delegate to `qa-engineer` (phase 2: execution) on the integrated branch. Triage defects; assign fixes as tasks to engineers. Check **G6**.
5. **3.7** For each branch, spawn `code-reviewer` and `security-reviewer` in one message. Route verdicts. Check **G7**.
6. **3.8** Delegate to `release-engineer` with the branch list in dependency order. Check **G8**.
7. **3.9** Delegate to `retrospective-analyst`. Apply accepted recommendations to templates/config; record rejected ones in `docs/DECISIONS.md`.
8. Rewrite `docs/STATUS.md`. Report to the human: tag, what shipped, defects deferred, debt, retro recommendations, spend.
