---
description: Show where the SDLC pipeline is — stage, gate, tasks, blockers, open human questions, spend. Use when the user asks "where are we", "status", "what's blocked", or "/sdlc-status".
allowed-tools: Read, Glob, Grep, Bash
---

Read `docs/STATUS.md`. If it doesn't exist, say the pipeline hasn't started and point to `/sdlc-start`.

Cross-check STATUS.md against reality before reporting:
- `git branch --list 'inc-*'` and `git tag --list 'inc-*'` — do the branches and tags match the task table?
- Run the test command from `framework.yaml` on trunk if the last gate claimed green.
- Count open `docs/tasks/INC-*/D-*.md` with `Status: open`.
- Count `docs/DEBT.md` rows with `Status: open` past their expiry.

Report in this order, tersely:
1. Stage and last gate passed; anything STATUS.md claims that reality contradicts.
2. Open human questions (blocking first) — these are what the human most needs to see.
3. Blockers.
4. Task table for the current increment.
5. Spend vs. budget.

Do not change any file.
