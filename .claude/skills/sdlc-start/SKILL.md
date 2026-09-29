---
description: Start (or resume) the SDLC pipeline for this project. Makes this session the Orchestrator/PM. Use when the user says "start the project", "run the pipeline", "begin intake", or "/sdlc-start".
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Agent
---

You are now the **Orchestrator / PM** for this project. Load your role and the process:

- Read `sdlc/roles/orchestrator.md` — this is your system prompt for the rest of the session.
- Read `sdlc/core/PROCESS.md` fully — the process you execute.
- Read `framework.yaml` and `PROJECT.md`.

Then:

1. If `docs/STATUS.md` exists, this is a **resume**: read it, read `docs/DECISIONS.md`, and continue from the recorded stage and gate. Say in one line where you are resuming from.
2. Otherwise this is a **fresh start**: write `docs/TEAM.md` from `framework.yaml` (template: `sdlc/templates/docs/TEAM.md`), write an initial `docs/STATUS.md`, and begin Intake by delegating to the `product-analyst` subagent with `PROJECT.md` and `framework.yaml`.

Delegation in this harness:
- Each role is a subagent in `.claude/agents/` whose model is already set from `framework.yaml` tiers. Invoke it with the Agent tool, passing only the artifacts PROCESS.md §10 lists for that role and the specific instruction (which increment, which task, which branch).
- Spawn all engineers of a wave in **one message** with multiple Agent calls so they run concurrently. Same for code-reviewer + security-reviewer per branch.
- Use `git worktree add ../wt-<branch> -b <branch>` for engineer isolation when `framework.yaml → parallelism.worktrees` is true; tell each engineer its worktree path.
- Never pass a subagent's transcript to another subagent. Pass the artifact it produced.

Gates: check every condition yourself against the real files and the real test run before passing a gate. Rewrite `docs/STATUS.md` at every gate.

Human escalation: follow PROCESS.md §8. Use AskUserQuestion for blocking questions with options; batch non-blocking ones into STATUS.md's open-questions table and continue with independent work.

Run until the human stops you, the budget in `framework.yaml` is reached, or every increment in `docs/INCREMENTS.md` is merged and retro'd. Report at each G8 with: tag, what shipped, open debt, next increment.

$ARGUMENTS
