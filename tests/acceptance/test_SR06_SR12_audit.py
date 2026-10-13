"""SR-6 / SR-12 workload audit: pre-principal aggregates, caps, sink rules (INC-2).

Owning tasks: T-11 (validation), T-12 (emitter), T-24 (in-memory sink), T-28 (server counts).
Expected failure on trunk: NotImplementedError('T-24') at `InMemoryAuditSink()` or
NotImplementedError('T-12') at `AuditEmitter(...)`.
"""

import os
from typing import Any

import pytest

from acc_channel import RecordingLogger, aggregate_counts, make_world, seal_frame
from acc_support import START_TIME, FakeClock
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
    validate_audit,
)
from teecustody_sim.backends import InMemoryAuditSink

INTERVAL_S = 60
CAP = 3
TS = int(START_TIME * 1000)


def _emitter(sink: Any, clock: FakeClock, cap: int = CAP) -> AuditEmitter:
    return AuditEmitter(
        sink,
        interval_s=INTERVAL_S,
        alert_cap=cap,
        clock=clock,
        rng=os.urandom,
        logger=RecordingLogger(),
    )


def _by_outcome(sink: InMemoryAuditSink, cls: AuditClass) -> dict[str, list[AuditRecord]]:
    out: dict[str, list[AuditRecord]] = {}
    for _key, record in sink.records(cls):
        out.setdefault(record.outcome, []).append(record)
    return out


def _distinct_subject(i: int) -> str:
    return f"{i:032x}"


def test_SR06_flood_yields_one_aggregate_per_outcome_with_the_exact_count() -> None:
    # Given an emitter and a flood of pre-principal failures of three kinds in one interval
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock)
    injected = {
        AggregateOutcome.REQUEST_INVALID: 7,
        AggregateOutcome.PREKEY_UNKNOWN: 3,
        AggregateOutcome.OPEN_FAILED: 1,
    }
    for outcome, n in injected.items():
        for _ in range(n):
            emitter.count(outcome)
    # When the interval has not ended
    emitter.tick()
    # Then nothing is written yet (counters live in memory, O(1) per event)
    assert sink.records() == []
    # When the interval ends
    clock.now += INTERVAL_S + 1
    emitter.tick()
    # Then there is exactly one AGGREGATE per outcome, count == injected, nothing for zero counts
    aggregates = _by_outcome(sink, AuditClass.AGGREGATE)
    assert {k: [r.count for r in v] for k, v in aggregates.items()} == {
        "REQUEST_INVALID": [7],
        "PREKEY_UNKNOWN": [3],
        "OPEN_FAILED": [1],
    }
    assert sink.records(AuditClass.ALERT) == [] and sink.records(AuditClass.EVENT) == []
    for _key, record in sink.records(AuditClass.AGGREGATE):
        assert record.interval_start is not None and record.interval_end is not None
        assert record.interval_start < record.interval_end


def test_SR06_each_interval_counts_afresh() -> None:
    # Given a flushed interval
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock)
    for _ in range(4):
        emitter.count(AggregateOutcome.REQUEST_STALE)
    clock.now += INTERVAL_S + 1
    emitter.tick()
    # When two more occur in the next interval
    for _ in range(2):
        emitter.count(AggregateOutcome.REQUEST_STALE)
    clock.now += INTERVAL_S + 1
    emitter.tick()
    # Then the second aggregate holds 2, not a running total
    counts = sorted(r.count for r in _by_outcome(sink, AuditClass.AGGREGATE)["REQUEST_STALE"])
    assert counts == [2, 4]


def test_SR06_closing_flushes_the_partial_interval() -> None:
    # Given counted events and a shutdown before the interval ends
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock)
    emitter.count(AggregateOutcome.OPEN_FAILED)
    emitter.count(AggregateOutcome.OPEN_FAILED)
    clock.now += 5
    # When the emitter is closed
    emitter.close()
    # Then the count is not lost
    assert [r.count for r in _by_outcome(sink, AuditClass.AGGREGATE)["OPEN_FAILED"]] == [2]


def test_SR06_channel_failures_become_bounded_aggregates_not_per_event_objects() -> None:
    # Given a channel under a flood of garbage and unknown-session frames
    world = make_world()
    for _ in range(25):
        world.server.process(b"\xff")
    for i in range(4):
        world.server.process(seal_frame(bytes(32), bytes(16), i, "t", 1))
    # When the aggregation interval ends
    counts = world.flush_aggregates()
    # Then the counts equal the injected occurrences, in at most one object per outcome
    assert counts == {"REQUEST_INVALID": 25, "SESSION_UNKNOWN": 4}
    assert len(world.sink.records(AuditClass.AGGREGATE)) == 2
    assert world.sink.records(AuditClass.ALERT) == [] and world.sink.records(AuditClass.EVENT) == []


def test_SR06_sink_refuses_count_on_non_aggregate_records() -> None:
    # Given the in-memory sink
    sink = InMemoryAuditSink()
    # When an ALERT carries a count
    with pytest.raises(AuditError) as exc:
        sink.append(
            AuditKey(AuditClass.ALERT, "00" * 16 + "/PREKEY_BURN_HIGH"),
            AuditRecord(outcome="PREKEY_BURN_HIGH", ts=TS, count=3),
        )
    # Then it is refused, and nothing is stored
    assert exc.value.code is AuditErrorCode.INVALID_ARGUMENT
    assert sink.records() == []


@pytest.mark.parametrize(
    ("key", "record"),
    [
        (  # AGGREGATE without a count
            AuditKey(AuditClass.AGGREGATE, "1/OPEN_FAILED/ab"),
            AuditRecord(outcome="OPEN_FAILED", ts=TS, interval_start=TS - 1, interval_end=TS),
        ),
        (  # AGGREGATE with count 0
            AuditKey(AuditClass.AGGREGATE, "1/OPEN_FAILED/ab"),
            AuditRecord(
                outcome="OPEN_FAILED", ts=TS, interval_start=TS - 1, interval_end=TS, count=0
            ),
        ),
        (  # AGGREGATE with count above MAX_COUNT
            AuditKey(AuditClass.AGGREGATE, "1/OPEN_FAILED/ab"),
            AuditRecord(
                outcome="OPEN_FAILED",
                ts=TS,
                interval_start=TS - 1,
                interval_end=TS,
                count=MAX_COUNT + 1,
            ),
        ),
        (  # AGGREGATE with an empty interval
            AuditKey(AuditClass.AGGREGATE, "1/OPEN_FAILED/ab"),
            AuditRecord(outcome="OPEN_FAILED", ts=TS, interval_start=TS, interval_end=TS, count=1),
        ),
        (  # interval on an EVENT
            AuditKey(AuditClass.EVENT, "abc"),
            AuditRecord(outcome="X", ts=TS, interval_start=TS - 1, interval_end=TS),
        ),
        (  # identifier that is not 32 lowercase hex (uppercase)
            AuditKey(AuditClass.EVENT, "abc"),
            AuditRecord(outcome="X", ts=TS, session_id="A" * 32),
        ),
        (  # identifier with a trailing newline (fullmatch, R-7)
            AuditKey(AuditClass.EVENT, "abc"),
            AuditRecord(outcome="X", ts=TS, request_id="a" * 32 + "\n"),
        ),
        (  # free-text outcome (could carry content)
            AuditKey(AuditClass.EVENT, "abc"),
            AuditRecord(outcome="not a code", ts=TS),
        ),
        (  # epoch beyond uint32
            AuditKey(AuditClass.EVENT, "abc"),
            AuditRecord(outcome="X", ts=TS, epoch=2**32),
        ),
        (  # key id with a path traversal
            AuditKey(AuditClass.EVENT, "../abc"),
            AuditRecord(outcome="X", ts=TS),
        ),
    ],
    ids=[
        "agg-no-count",
        "agg-zero",
        "agg-over-max",
        "agg-empty-interval",
        "event-interval",
        "uppercase-id",
        "newline-id",
        "free-text-outcome",
        "epoch-range",
        "bad-key",
    ],
)
def test_SR06_audit_validation_rejects_out_of_contract_records(
    key: AuditKey, record: AuditRecord
) -> None:
    # Given a record outside the audit contract
    # When validated, or appended to the sink (which validates first)
    with pytest.raises(AuditError) as exc:
        validate_audit(key, record)
    assert exc.value.code is AuditErrorCode.INVALID_ARGUMENT
    sink = InMemoryAuditSink()
    with pytest.raises(AuditError):
        sink.append(key, record)
    # Then nothing is stored
    assert sink.records() == []


def test_SR06_sink_is_create_if_absent_and_never_overwrites() -> None:
    # Given an object that already exists
    sink = InMemoryAuditSink()
    key = AuditKey(AuditClass.EVENT, "evt1")
    first = AuditRecord(outcome="FIRST", ts=TS)
    assert sink.append(key, first) is AppendResult.CREATED
    # When the same key is written again with different content
    result = sink.append(key, AuditRecord(outcome="SECOND", ts=TS + 1))
    # Then the sink reports the conflict and keeps the original
    assert result is AppendResult.ALREADY_EXISTS
    assert [(k, r.outcome) for k, r in sink.records()] == [(key, "FIRST")]


class _ConflictOnce:
    """Reports ALREADY_EXISTS for the first AGGREGATE append (a pre-existing object)."""

    def __init__(self, inner: InMemoryAuditSink) -> None:
        self.inner, self.conflicted = inner, False

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        if key.record_class is AuditClass.AGGREGATE and not self.conflicted:
            self.conflicted = True
            return AppendResult.ALREADY_EXISTS
        return self.inner.append(key, record)


def test_SR06_a_preexisting_object_raises_a_conflict_alert_not_an_overwrite() -> None:
    # Given a sink where the aggregate's object name is already taken
    inner, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(_ConflictOnce(inner), clock)
    emitter.count(AggregateOutcome.REQUEST_INVALID)
    clock.now += INTERVAL_S + 1
    # When the emitter flushes
    emitter.tick()
    # Then an AUDIT_WRITE_CONFLICT alert is written individually, without a count
    alerts = _by_outcome(inner, AuditClass.ALERT)
    assert len(alerts["AUDIT_WRITE_CONFLICT"]) == 1
    assert alerts["AUDIT_WRITE_CONFLICT"][0].count is None


def test_SR06_an_unavailable_sink_keeps_the_record_and_retries_without_duplicating() -> None:
    # Given a sink that fails the next write
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock)
    emitter.count(AggregateOutcome.OPEN_FAILED)
    sink.fail_next(1)
    clock.now += INTERVAL_S + 1
    # When the emitter flushes (it never raises into the channel)
    emitter.tick()
    assert sink.records(AuditClass.AGGREGATE) == []
    # And retries on the next tick
    emitter.tick()
    # Then exactly one aggregate with the right count exists
    assert [r.count for r in _by_outcome(sink, AuditClass.AGGREGATE)["OPEN_FAILED"]] == [1]


def test_SR12_alert_cap_applies_only_to_pre_principal_alerts() -> None:
    # Given an alert cap of 3 and a sink
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock, cap=CAP)
    # When more than the cap of anonymous KCV_MISMATCH events arrive for distinct subjects
    for i in range(1, 6):
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_distinct_subject(i))
    # And, in the same interval, the non-pre-principal alerts fire
    emitter.alert("TRUSTEE_SHARE_REJECTED")
    emitter.alert("AUDIT_WRITE_CONFLICT")
    start = TS
    emitter.alert("PREKEY_BURN_HIGH", interval=(start, start + 60_000))
    # And a repeat for subject 1 and one more previously unseen subject
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_distinct_subject(1))
    emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_distinct_subject(6))
    # Then each of the three non-pre-principal alerts is written individually
    alerts = _by_outcome(sink, AuditClass.ALERT)
    for code in ("TRUSTEE_SHARE_REJECTED", "AUDIT_WRITE_CONFLICT", "PREKEY_BURN_HIGH"):
        assert len(alerts[code]) == 1
    burn = alerts["PREKEY_BURN_HIGH"][0]
    assert burn.interval_start is not None and burn.interval_end is not None
    # And only `cap` KCV_MISMATCH alerts exist, plus exactly one ALERT_CAP_REACHED
    assert len(alerts["KCV_MISMATCH"]) == CAP
    assert len(alerts["ALERT_CAP_REACHED"]) == 1
    # And the total is bounded by cap + 1 + the uncapped alerts
    assert sum(len(v) for v in alerts.values()) <= CAP + 1 + 3
    assert all(r.count is None for v in alerts.values() for r in v)
    # And the over-cap and repeated events are in the interval's KCV_MISMATCH aggregate
    clock.now += INTERVAL_S + 1
    emitter.tick()
    assert aggregate_counts(sink)["KCV_MISMATCH"] == 4  # subjects 4, 5, 6 + the repeat of 1


def test_SR12_audit_flood_never_raises_into_the_caller() -> None:
    # Given an emitter whose sink keeps failing
    sink, clock = InMemoryAuditSink(), FakeClock()
    emitter = _emitter(sink, clock)
    sink.fail_next(1000)
    # When many events and ticks happen
    for i in range(200):
        emitter.count(AggregateOutcome.REQUEST_INVALID)
        emitter.pre_principal_alert("KCV_MISMATCH", subject_client_id=_distinct_subject(i))
        clock.now += INTERVAL_S + 1
        emitter.tick()
    # Then no exception escapes and no record is invented
    emitter.close()
    assert sink.records() == []
