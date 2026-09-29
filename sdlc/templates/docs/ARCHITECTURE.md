# Architecture — <project>

Status: draft | approved(G2) | security-approved(G3)   Last change: <date, by role, reason>

## 1. Context
<What the system is, its external actors and systems. A context diagram (Mermaid or ASCII).>

## 2. Requirement trace
| Requirement | Component(s) | Notes |
|---|---|---|
| FR-1 | | |

## 3. Components and layering
Layering: <hexagonal | clean | layered>. Dependencies point inward.

| Component | Layer | Responsibility | Depends on |
|---|---|---|---|

<Component diagram.>

## 4. Contracts
<!-- One subsection per boundary that may be split across engineers. Copied verbatim into Task Contracts. -->
### 4.1 <Boundary name> (`<provider>` → `<consumer>`)
```
<exact types / signatures / schema / endpoint spec>
```
Error semantics: <what is raised/returned on each failure class>
Invariants: <what always holds>

## 5. Data model
<Entities, relationships, ownership, source of truth, migration strategy.>

## 6. Cross-cutting
- Error handling:
- Logging / observability:
- Configuration and secrets access:
- i18n / RTL (if required):
- Concurrency model:

## 7. Test strategy
| Layer | Location | Scope | Fixtures / data policy |
|---|---|---|---|
| Unit | tests/unit | | |
| Integration / contract | tests/integration | | |
| Acceptance | tests/acceptance | | |

## 8. Deployment shape
<Runtime topology, environments, how it's built and run. Must match framework.yaml → stack.deployment.>

## 9. Decisions
| ADR | Title | Status |
|---|---|---|
| 0001 | | accepted |

## 10. Known risks
<Riskiest assumptions, and what would invalidate them.>
