"""T-12 unit tests for the audit emitter (INC-2-API §4.12, §10; SR-6, SR-11, SR-12, D-012)."""

import re

from teecustody.audit import (
    MAX_COUNT,
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


def test_count_saturates_at_max_count() -> None:
    emitter, sink, clock, _ = _make()
    emitter._counts[AggregateOutcome.OPEN_FAILED.value] = MAX_COUNT - 5  # private seed
    for _ in range(10):
        emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now += INTERVAL_S
    emitter.tick()
    [(_, record)] = sink.of(AuditClass.AGGREGATE)
    assert record.count == MAX_COUNT


SUBJECT_A = "a" * 32
SUBJECT_B = "b" * 32
REQ = "c" * 32


def test_pre_principal_alert_first_per_subject_alerts_and_repeats_fold() -> None:
    emitter, sink, clock, _ = _make()
    emitter.pre_principal_alert(
        "KCV_MISMATCH", subject_client_id=SUBJECT_A, request_id=REQ, epoch=7
    )
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_B, recovery_id="d" * 32)
    alerts = sink.of(AuditClass.ALERT)
    assert [r.subject_client_id for _, r in alerts] == [SUBJECT_A, SUBJECT_B]
    for key, record in alerts:
        match = ALERT_ID.fullmatch(key.id)
        assert match is not None
        assert match.group(2) == "KCV_MISMATCH"
        assert record.outcome == "KCV_MISMATCH"
        assert record.ts == START_MS
        assert record.count is None
    assert (alerts[0][1].request_id, alerts[0][1].epoch, alerts[0][1].recovery_id) == (REQ, 7, None)
    assert (alerts[1][1].request_id, alerts[1][1].recovery_id) == (None, "d" * 32)
    assert alerts[0][0].id != alerts[1][0].id
    assert sink.of(AuditClass.AGGREGATE) == []
    clock.now += INTERVAL_S
    emitter.tick()
    [(_, aggregate)] = sink.of(AuditClass.AGGREGATE)
    assert aggregate.outcome == "KCV_MISMATCH"
    assert aggregate.count == 1


def _subject(i: int) -> str:
    return f"{i:032x}"


def test_alert_cap_writes_one_cap_reached_then_folds_and_resets_next_interval() -> None:
    emitter, sink, clock, _ = _make(cap=2)
    for i in range(5):
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_subject(i))
    outcomes = [r.outcome for _, r in sink.of(AuditClass.ALERT)]
    assert outcomes == ["KCV_MISMATCH", "KCV_MISMATCH", "ALERT_CAP_REACHED"]
    [(cap_key, cap_record)] = sink.of(AuditClass.ALERT)[2:]
    assert ALERT_ID.fullmatch(cap_key.id) is not None
    assert cap_record.subject_client_id is None
    assert cap_record.count is None
    clock.now += INTERVAL_S
    emitter.tick()
    [(_, aggregate)] = sink.of(AuditClass.AGGREGATE)
    assert aggregate.count == 3
    for i in (0, 5, 6):
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_subject(i))
    outcomes = [r.outcome for _, r in sink.of(AuditClass.ALERT)]
    assert outcomes == ["KCV_MISMATCH"] * 2 + ["ALERT_CAP_REACHED"] + ["KCV_MISMATCH"] * 2 + [
        "ALERT_CAP_REACHED"
    ]
    assert sink.of(AuditClass.ALERT)[3][1].subject_client_id == _subject(0)


def test_alert_is_never_capped_or_deduplicated() -> None:
    emitter, sink, _, _ = _make(cap=1)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_B)
    span = (START_MS - INTERVAL_MS, START_MS)
    for _ in range(200):
        emitter.alert("PREKEY_BURN_HIGH", interval=span)
    emitter.alert("AUDIT_WRITE_CONFLICT", request_id=REQ)
    burns = [(k, r) for k, r in sink.of(AuditClass.ALERT) if r.outcome == "PREKEY_BURN_HIGH"]
    assert len(burns) == 200
    assert len({k.id for k, _ in burns}) == 200
    for key, record in burns:
        match = ALERT_ID.fullmatch(key.id)
        assert match is not None
        assert match.group(2) == "PREKEY_BURN_HIGH"
        assert (record.interval_start, record.interval_end) == span
        assert record.count is None
        assert record.request_id is None
        assert record.ts == START_MS
    [(_, conflict)] = [
        r for r in sink.of(AuditClass.ALERT) if r[1].outcome == "AUDIT_WRITE_CONFLICT"
    ]
    assert conflict.request_id == REQ
    assert conflict.interval_start is None
    assert conflict.interval_end is None
