# T-nn: <imperative title>

Increment: INC-N   Wave: k   Tier: MID   Depends on: T-aa, T-bb
Requirements covered: FR-3, FR-7, SR-2
Branch: inc-N/T-nn-<slug>

## Goal
One paragraph: what exists when this is done and why it matters to the increment.

## Owned files
- `src/module/x.py` (create)
- `src/module/y.py` (modify: add function `foo`; do not change `bar`)
- `tests/unit/test_x.py` (create)

Touching any other file is out of scope — return CONTRACT_ISSUE instead.

## Interface contract
Copied verbatim from ARCHITECTURE.md § <section>. Exact signatures / schemas / endpoints this task **implements**, and those it **consumes** from earlier waves. Include error semantics (what is raised/returned on each failure class).

```
<signatures / schema>
```

## Acceptance criteria (each becomes a test, in this order)
1. Given <precondition>, when <action>, then <observable result>.
2. Given …, when …, then … .
3. Given <invalid input>, when …, then <specified error> and no side effect.

## Security requirements
- SR-2: <what "satisfied" looks like in this task, and the test that proves it>

## Constraints
- Coding standards: framework.yaml → coding_standards
- Allowed new dependencies: none | <list>
- Performance budget: <if any>
- Logging: <what must / must not be logged>

## Definition of done
- [ ] Every acceptance criterion has a passing test that was seen failing first
- [ ] Every SR-n above has a passing test that proves the control
- [ ] No commit adds production code without a test change (pure refactors excepted)
- [ ] Full suite green, lint clean, coverage on owned files ≥ threshold
- [ ] No TODOs, no commented-out code, no debug output, no secrets
- [ ] Only owned files touched
- [ ] Task Report submitted
