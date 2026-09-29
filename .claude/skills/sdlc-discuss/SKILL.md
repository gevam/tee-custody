---
description: Convene a bounded discussion between two or three roles on one decidable question (PROCESS.md §11). Use when two roles conflict on a blocking decision, or the user says "/sdlc-discuss".
disable-model-invocation: true
allowed-tools: Read, Write, Edit, Glob, Grep, Agent
arguments: [question, participants]
---

You chair a **bounded discussion** per `sdlc/core/PROCESS.md` §11. Read `framework.yaml → discussion` for the limits.

Question: $question
Participants: $participants

Before convening, apply the cost rule: if the reversal cost of this decision is low, do not convene — decide, write a Decision Record to `docs/DECISIONS.md`, and stop. Also check the per-increment cap in `docs/STATUS.md`; if hit, decide unilaterally and note the cap for the retro.

Otherwise:

1. Write the convening block: the question as one sentence answerable by a choice or yes/no; participants (2–3); chair (the role that owns the decision per PROCESS.md §6 — yourself if that is the Orchestrator); round limit (`discussion.default_rounds`); word budget (`discussion.words_per_round`); inputs (the artifact paths participants may cite — nothing else).
2. **Round 1:** spawn one `discussion-participant` subagent per participant **in a single message**, each given: the convening block, `sdlc/roles/<their-role>.md` so they keep that perspective, the input artifacts, and the instruction "Round 1". They must not see each other's answers.
3. **Round 2:** spawn each again with all Round-1 positions and the instruction "Round 2".
4. **Round 3** only if the answers still diverge on a point that decides the outcome and `discussion.max_rounds` allows it: one narrowed question, half the word budget.
5. **Decide.** Do not extend rounds to seek consensus. Write a Decision Record (`sdlc/templates/DECISION_RECORD.md`) to `docs/DECISIONS.md` with verbatim dissent. If the question meets PROCESS.md §8, escalate to the human with the two best options and your recommendation instead of deciding.
6. Increment the discussion count in `docs/STATUS.md`.

Discard overflow beyond the word budget. Report to the human in ≤5 lines: question, decision, dissent, follow-ups.
