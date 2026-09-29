# Team — tee-custody

Written by the Orchestrator at project start from `framework.yaml`. Source of truth for who runs what.

## Tier → model
| Tier | Model | Thinking | Roles |
|---|---|---|---|
| VERY_STRONG | fable | extended | orchestrator, product-analyst |
| STRONG | opus | extended | architect, security-architect, tech-lead, code-reviewer, security-reviewer |
| MID | sonnet | standard | software-engineer, qa-engineer, retrospective-analyst |
| FAST | haiku | standard | release-engineer |

## Thresholds in force
| Setting | Value | Source |
|---|---|---|
| coverage.line_min | 80% | framework.yaml |
| coverage.security_paths_min | 100% | framework.yaml |
| review.max_rounds | 2 | framework.yaml |
| review.tdd_spot_checks | 3 | framework.yaml |
| parallelism.max_engineers | 4 | framework.yaml |
| discussion.max_rounds / words_per_round / max_per_increment | 3 / 400 / 3 | framework.yaml |
| escalation.effort_growth_pct / max_review_failures / max_gate_failures | 30% / 3 / 3 | framework.yaml |
| budget.total_tokens / per_increment_tokens | 0 (unlimited) / 0 (unlimited) | framework.yaml |

## Commands
| Purpose | Command |
|---|---|
| test | `uv run pytest -q packages/teecustody-py packages/teecustody-sim && pnpm -r test && uv run pytest -q spec/vectors` |
| lint | `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict packages/teecustody-py/src packages/teecustody-sim/src && pnpm -r lint && pnpm -r typecheck` |
| coverage | `uv run pytest --cov=teecustody --cov-report=term-missing packages/teecustody-py && pnpm -r coverage` |

## Security
Scanners: bandit, pip-audit, gitleaks, semgrep, pnpm-audit, trivy. Dependency policy: OSI licences only; release within the last 18 months; cryptographic dependencies limited to the explicitly approved set in `framework.yaml`, exact-version and hash pinned; new or replacement crypto dependencies require an ADR and Security Architect sign-off. Residual risk acceptor: human.
