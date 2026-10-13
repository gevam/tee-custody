"""T-12 unit tests for the audit emitter (INC-2-API §4.12, §10; SR-6, SR-11, SR-12, D-012)."""

import re

from teecustody.audit import (
    AggregateOutcome,
    AppendResult,
    AuditClass,
    AuditEmitter,
    AuditKey,
    AuditRecord,
)
from teecustody.obs.types import FieldValue

START = 1_700_000_000.0
START_MS = int(START * 1000)
INTERVAL_S = 60
INTERVAL_MS = INTERVAL_S * 1000


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class CountingRng:
    """Deterministic: the k-th call returns k as a big-endian integer of the requested width."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, n: int) -> bytes:
        self.calls += 1
        return self.calls.to_bytes(n, "big")


class RecordingLogger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str, dict[str, FieldValue]]] = []

    def info(self, outcome: str, **fields: FieldValue) -> None:
        self.lines.append(("info", outcome, fields))

    def warning(self, outcome: str, **fields: FieldValue) -> None:
        self.lines.append(("warning", outcome, fields))

    def error(self, outcome: str, **fields: FieldValue) -> None:
        self.lines.append(("error", outcome, fields))


class FakeSink:
    """Create-if-absent; `faults` is consumed one per append (an exception, a result, or None)."""

    def __init__(self) -> None:
        self.stored: dict[AuditKey, AuditRecord] = {}
        self.order: list[AuditKey] = []
        self.faults: list[BaseException | AppendResult | None] = []
        self.attempts = 0

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        self.attempts += 1
        if self.faults:
            fault = self.faults.pop(0)
            if isinstance(fault, BaseException):
                raise fault
            if fault is not None:
                return fault
        if key in self.stored:
            return AppendResult.ALREADY_EXISTS
        self.stored[key] = record
        self.order.append(key)
        return AppendResult.CREATED

    def of(self, cls: AuditClass) -> list[tuple[AuditKey, AuditRecord]]:
        return [(k, self.stored[k]) for k in self.order if k.record_class is cls]


def _make(
    sink: FakeSink | None = None, *, cap: int = 100
) -> tuple[AuditEmitter, FakeSink, FakeClock, RecordingLogger]:
    sink = sink if sink is not None else FakeSink()
    clock, logger = FakeClock(), RecordingLogger()
    emitter = AuditEmitter(
        sink, interval_s=INTERVAL_S, alert_cap=cap, clock=clock, rng=CountingRng(), logger=logger
    )
    return emitter, sink, clock, logger


AGG_ID = re.compile(r"(\d+)/([A-Z][A-Z0-9_]*)/([0-9a-f]{16})")
ALERT_ID = re.compile(r"([0-9a-f]{32})/([A-Z][A-Z0-9_]*)")


def test_one_aggregate_per_outcome_with_exact_count_after_interval_ends() -> None:
    emitter, sink, clock, _ = _make()
    outcomes = list(AggregateOutcome)
    counted = outcomes[:-1]
    for n, outcome in enumerate(counted, start=1):
        for _ in range(n):
            emitter.count(outcome)
    emitter.tick()
    assert sink.stored == {}
    clock.now = START + INTERVAL_S + 1.5
    emitter.tick()
    aggregates = sink.of(AuditClass.AGGREGATE)
    assert len(aggregates) == len(counted) == len(sink.stored)
    by_outcome = {r.outcome: (k, r) for k, r in aggregates}
    assert outcomes[-1].value not in by_outcome
    for n, outcome in enumerate(counted, start=1):
        key, record = by_outcome[outcome.value]
        match = AGG_ID.fullmatch(key.id)
        assert match is not None
        assert match.group(1) == str(START_MS)
        assert match.group(2) == outcome.value
        assert record.count == n
        assert record.interval_start == START_MS
        assert record.interval_end == START_MS + INTERVAL_MS
        assert record.ts == START_MS + INTERVAL_MS + 1500
        assert record.subject_client_id is None
        assert record.request_id is None
    assert len({k.id for k, _ in aggregates}) == len(aggregates)
