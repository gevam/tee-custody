---
description: Check one pipeline gate (G1–G8) against the real artifacts and test run, and report pass/fail with the specific unmet conditions. Use when the user says "check gate 4", "are we past G7", or "/sdlc-gate N".
allowed-tools: Read, Glob, Grep, Bash
arguments: [gate]
---

Check gate **G$gate** as defined in `sdlc/core/PROCESS.md` §3. Read the gate's conditions from PROCESS.md, then verify each against reality — open the files, run the commands. Never take `docs/STATUS.md` or a Task Report's word for it.

Per gate, the evidence to collect:
- **G1** — every FR/NFR row in `docs/REQUIREMENTS.md` has a non-empty acceptance criterion; the `[HUMAN]` table is empty or every row has an answer recorded in `docs/DECISIONS.md`; grep for "TBD".
- **G2** — the requirement-trace table in `docs/ARCHITECTURE.md` covers every FR/NFR id; every boundary in §3 has a §4 contract; INC-1 in `docs/INCREMENTS.md` lists ≤ ~8 tasks' worth of scope.
- **G3** — `docs/THREAT_MODEL.md` exists; every threat with severity High/Critical has a mitigation and an SR; every SR in REQUIREMENTS.md has a test description; residual-risk table has an "Accepted by" value.
- **G4** — for the current increment: no file appears under "Owned files" in two contracts of the same wave (script it); every `Depends on` id is in an earlier wave; run the test command — the acceptance tests for this increment exist and **fail**; contract test stubs exist under `tests/integration/contracts/`.
- **G5** — every task in WAVES.md has a Task Report with DONE; run the suite on each branch (or the integration branch): green; run coverage: ≥ `framework.yaml → coverage.line_min`.
- **G6** — `docs/qa/INC-N.md` exists; every acceptance criterion marked pass; no `D-*.md` with severity Critical/High and status open; Medium/Low open ones have a deferral with human sign-off.
- **G7** — each branch has both APPROVE verdicts recorded in `docs/DECISIONS.md` or STATUS.md; no security finding ≥ High unresolved.
- **G8** — trunk suite green; tag `inc-N` exists and points at trunk; `CHANGELOG.md` has the `inc-N` section.

Report: **PASS** or **FAIL**, then the unmet conditions as a checklist with the evidence (file:line, command output excerpt). If FAIL, name the owning role per PROCESS.md §6. Do not change any file.
