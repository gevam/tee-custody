# Team — <project>

Written by the Orchestrator at project start from `framework.yaml`. Source of truth for who runs what.

## Tier → model
| Tier | Model | Thinking | Roles |
|---|---|---|---|
| VERY_STRONG | | | orchestrator, product-analyst |
| STRONG | | | architect, security-architect, tech-lead, code-reviewer, security-reviewer |
| MID | | | software-engineer, qa-engineer, retrospective-analyst |
| FAST | | | release-engineer |

## Thresholds in force
| Setting | Value | Source |
|---|---|---|
| coverage.line_min | | framework.yaml |
| coverage.security_paths_min | | |
| review.max_rounds | | |
| review.tdd_spot_checks | | |
| parallelism.max_engineers | | |
| discussion.max_rounds / words_per_round / max_per_increment | | |
| escalation.effort_growth_pct / max_review_failures / max_gate_failures | | |
| budget.total_tokens / per_increment_tokens | | |

## Commands
| Purpose | Command |
|---|---|
| test | |
| lint | |
| coverage | |

## Security
Scanners: <list>   Dependency policy: <text>   Residual risk acceptor: human
