"""T-12 unit tests for the audit emitter (INC-2-API §4.12, §10; SR-6, SR-11, SR-12, D-012)."""

import re

import pytest

from teecustody.audit import (
    MAX_COUNT,
    AggregateOutcome,
    AppendResult,
    AuditClass,
    AuditEmitter,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
)
from teecustody.audit.emitter import PROTECTED_PENDING_MAX
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


def _conflicts(sink: FakeSink) -> list[tuple[AuditKey, AuditRecord]]:
    return [(k, r) for k, r in sink.of(AuditClass.ALERT) if r.outcome == "AUDIT_WRITE_CONFLICT"]


def test_already_exists_writes_a_conflict_alert_with_a_fresh_id() -> None:
    emitter, sink, clock, _ = _make()
    sink.faults = [AppendResult.ALREADY_EXISTS]
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A, request_id=REQ)
    [(conflict_key, conflict)] = _conflicts(sink)
    assert [r.outcome for _, r in sink.of(AuditClass.ALERT)] == ["AUDIT_WRITE_CONFLICT"]
    assert conflict.request_id == REQ
    assert conflict.subject_client_id is None
    assert conflict.count is None
    assert ALERT_ID.fullmatch(conflict_key.id) is not None
    emitter.count(AggregateOutcome.OPEN_FAILED)
    sink.faults = [AppendResult.ALREADY_EXISTS]
    clock.now += INTERVAL_S
    emitter.tick()
    assert sink.of(AuditClass.AGGREGATE) == []
    conflicts = _conflicts(sink)
    assert len(conflicts) == 2
    assert conflicts[1][1].request_id is None
    assert len({k.id for k, _ in conflicts}) == 2


def test_a_conflicting_conflict_alert_is_not_retried_on_conflict_again() -> None:
    emitter, sink, _, logger = _make()
    sink.faults = [AppendResult.ALREADY_EXISTS, AppendResult.ALREADY_EXISTS]
    emitter.alert("PREKEY_BURN_HIGH", interval=(START_MS - INTERVAL_MS, START_MS))
    assert sink.attempts == 2
    assert sink.stored == {}
    assert logger.lines == [("error", "AUDIT_WRITE_FAILED", {})]
    emitter.tick()
    assert sink.attempts == 2


PENDING_MAX = 2 * len(AggregateOutcome)


def _unavailable(n: int) -> list[BaseException | AppendResult | None]:
    return [AuditError(AuditErrorCode.UNAVAILABLE) for _ in range(n)]


def test_unavailable_keeps_a_bounded_sheddable_queue_and_retries_on_tick() -> None:
    emitter, sink, _, logger = _make()
    sink.faults = _unavailable(30)
    for i in range(30):
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_subject(i))
    assert sink.stored == {}
    assert PENDING_MAX == 24
    dropped = ("warning", "AUDIT_PENDING_DROPPED_KCV_MISMATCH", {})
    assert logger.lines == [dropped] * (30 - PENDING_MAX)
    emitter.tick()
    written = [r.subject_client_id for _, r in sink.of(AuditClass.ALERT)]
    assert written == [_subject(i) for i in range(30 - PENDING_MAX, 30)]
    attempts = sink.attempts
    emitter.tick()
    assert sink.attempts == attempts


def test_retry_stops_at_the_first_unavailable_and_keeps_order() -> None:
    emitter, sink, clock, _ = _make()
    sink.faults = _unavailable(3)
    for i in range(3):
        emitter.alert("AUDIT_WRITE_CONFLICT", request_id=_subject(i))
    sink.faults = _unavailable(1)
    emitter.tick()
    assert sink.attempts == 4
    assert sink.stored == {}
    emitter.count(AggregateOutcome.OPEN_FAILED)
    sink.faults = _unavailable(2)
    clock.now += INTERVAL_S
    emitter.tick()
    assert sink.stored == {}
    emitter.tick()
    outcomes = [sink.stored[k].outcome for k in sink.order]
    assert outcomes == ["AUDIT_WRITE_CONFLICT"] * 3 + ["OPEN_FAILED"]
    [(_, aggregate)] = sink.of(AuditClass.AGGREGATE)
    assert aggregate.count == 1


def test_close_flushes_the_partial_interval_ending_now() -> None:
    emitter, sink, clock, _ = _make()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    emitter.count(AggregateOutcome.OPEN_FAILED)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A)
    clock.now += 12.345
    emitter.close()
    aggregates = {r.outcome: r for _, r in sink.of(AuditClass.AGGREGATE)}
    assert {k: r.count for k, r in aggregates.items()} == {"OPEN_FAILED": 2, "KCV_MISMATCH": 1}
    for record in aggregates.values():
        assert record.interval_start == START_MS
        assert record.interval_end == START_MS + 12_345
        assert record.ts == START_MS + 12_345


SENTINEL = "SENTINEL-payload-0123456789"


@pytest.mark.parametrize(
    "error",
    [
        AuditError(AuditErrorCode.INVALID_ARGUMENT),
        RuntimeError(SENTINEL),
        ValueError(SENTINEL),
        KeyError(SENTINEL),
    ],
    ids=["invalid-argument", "runtime", "value", "key"],
)
def test_no_method_raises_and_failures_are_logged_without_fields(error: Exception) -> None:
    class Raising(FakeSink):
        def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
            self.attempts += 1
            raise error

    sink = Raising()
    emitter, _, clock, logger = _make(sink, cap=1)
    emitter.count(AggregateOutcome.REQUEST_INVALID)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A, request_id=REQ)
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_B)
    emitter.alert("PREKEY_BURN_HIGH", interval=(START_MS - INTERVAL_MS, START_MS))
    clock.now += INTERVAL_S
    emitter.tick()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    emitter.close()
    assert sink.attempts == 6
    assert logger.lines == [("error", "AUDIT_WRITE_FAILED", {})] * 6
    assert SENTINEL not in repr(logger.lines)
    emitter.tick()
    assert sink.attempts == 6


def test_close_at_the_interval_start_still_writes_a_non_empty_interval() -> None:
    emitter, sink, _, _ = _make()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    emitter.close()
    [(_, record)] = sink.of(AuditClass.AGGREGATE)
    assert record.interval_start == START_MS
    assert record.interval_end == START_MS + 1


def test_a_clock_jump_skips_empty_intervals_and_keeps_them_contiguous() -> None:
    emitter, sink, clock, _ = _make()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now = START + 10.5 * INTERVAL_S
    emitter.tick()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now = START + 11.5 * INTERVAL_S
    emitter.tick()
    intervals = [(r.interval_start, r.interval_end) for _, r in sink.of(AuditClass.AGGREGATE)]
    assert intervals == [
        (START_MS, START_MS + INTERVAL_MS),
        (START_MS + 10 * INTERVAL_MS, START_MS + 11 * INTERVAL_MS),
    ]


def test_a_retry_that_finds_its_record_already_written_raises_one_conflict_alert() -> None:
    emitter, sink, _, _ = _make()
    sink.faults = [*_unavailable(1), AppendResult.ALREADY_EXISTS]
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=SUBJECT_A, request_id=REQ)
    emitter.tick()
    [(_, conflict)] = sink.of(AuditClass.ALERT)
    assert conflict.outcome == "AUDIT_WRITE_CONFLICT"
    assert conflict.request_id == REQ
    attempts = sink.attempts
    emitter.tick()
    assert sink.attempts == attempts


@pytest.mark.parametrize(
    ("outcome", "log"),
    [
        ("A" * 42, "AUDIT_PENDING_DROPPED_" + "A" * 42),
        ("A" * 43, "AUDIT_PENDING_DROPPED"),
        ("kcv mismatch", "AUDIT_PENDING_DROPPED"),
    ],
    ids=["64-chars", "65-chars", "not-a-code"],
)
def test_drop_log_falls_back_when_the_named_outcome_is_not_a_valid_code(
    outcome: str, log: str
) -> None:
    emitter, sink, _, logger = _make()
    sink.faults = _unavailable(PENDING_MAX + 1)
    for i in range(PENDING_MAX + 1):
        emitter.pre_principal_alert(outcome, subject_client_id=_subject(i))
    assert logger.lines == [("warning", log, {})]


class OutageSink(FakeSink):
    """UNAVAILABLE for every append while `down`."""

    def __init__(self) -> None:
        super().__init__()
        self.down = True

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        if self.down:
            self.attempts += 1
            raise AuditError(AuditErrorCode.UNAVAILABLE)
        return super().append(key, record)


def test_an_anonymous_flood_during_an_outage_never_evicts_an_authenticated_alert() -> None:
    sink = OutageSink()
    emitter, _, clock, logger = _make(sink)
    span = (START_MS - INTERVAL_MS, START_MS)
    emitter.alert("PREKEY_BURN_HIGH", interval=span)
    for i in range(101):
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_subject(i))
    sink.down = False
    clock.now += INTERVAL_S
    emitter.tick()
    alerts = [r for _, r in sink.of(AuditClass.ALERT)]
    assert alerts[0].outcome == "PREKEY_BURN_HIGH"
    assert (alerts[0].interval_start, alerts[0].interval_end) == span
    assert [r.outcome for r in alerts[1:]] == ["ALERT_CAP_REACHED"] + ["KCV_MISMATCH"] * PENDING_MAX
    assert [r.subject_client_id for r in alerts[2:]] == [_subject(i) for i in range(76, 100)]
    assert logger.lines == [("warning", "AUDIT_PENDING_DROPPED_KCV_MISMATCH", {})] * 76


def test_protected_pending_is_bounded_at_256_dropping_the_oldest() -> None:
    sink = OutageSink()
    emitter, _, _, logger = _make(sink)
    assert PROTECTED_PENDING_MAX == 256
    for i in range(PROTECTED_PENDING_MAX + 1):
        emitter.alert("AUDIT_WRITE_CONFLICT", request_id=_subject(i))
    assert logger.lines == [("warning", "AUDIT_PENDING_DROPPED_AUDIT_WRITE_CONFLICT", {})]
    sink.down = False
    emitter.tick()
    written = [r.request_id for _, r in sink.of(AuditClass.ALERT)]
    assert written == [_subject(i) for i in range(1, PROTECTED_PENDING_MAX + 1)]


def test_a_backward_clock_ends_the_interval_at_its_nominal_end_and_restarts_at_now() -> None:
    emitter, sink, clock, logger = _make()
    emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now = START - 500
    emitter.tick()
    [(key, record)] = sink.of(AuditClass.AGGREGATE)
    assert (record.interval_start, record.interval_end) == (START_MS, START_MS + INTERVAL_MS)
    assert record.count == 1
    assert key.id.startswith(f"{START_MS}/OPEN_FAILED/")
    assert logger.lines == [("warning", "AUDIT_CLOCK_BACKWARD", {})]
    emitter.tick()
    assert logger.lines == [("warning", "AUDIT_CLOCK_BACKWARD", {})]
    emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now = START - 500 + INTERVAL_S
    emitter.tick()
    second = sink.of(AuditClass.AGGREGATE)[1][1]
    restart = START_MS - 500_000
    assert (second.interval_start, second.interval_end) == (restart, restart + INTERVAL_MS)
