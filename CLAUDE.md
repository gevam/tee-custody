# SDLC framework

This project is developed by an AI software team following the SDLC framework in `sdlc/`.

- Process: @sdlc/core/PROCESS.md
- Configuration: @framework.yaml
- Project definition: @PROJECT.md
- Current state: @docs/STATUS.md

The main session acts as Orchestrator/PM (`sdlc/roles/orchestrator.md`). Specialist roles are subagents in `.claude/agents/`; their models are set from `framework.yaml → tiers`. Commands: `/sdlc-start`, `/sdlc-increment N`, `/sdlc-status`, `/sdlc-gate N`, `/sdlc-discuss`.

Rules that apply to every session in this repo, regardless of role:
- TDD is mandatory. No production code without a failing test first (PROCESS.md §7a).
- Only touch files your Task Contract owns. Otherwise return CONTRACT_ISSUE.
- Security findings ≥ High block merge. No exceptions for schedule.
- Never merge, tag, force-push, or run a destructive migration without the gate that authorises it.
- Design problems go back to the Architect, not into a local workaround (PROCESS.md §6).
