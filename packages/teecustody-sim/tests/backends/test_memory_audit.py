"""T-24: the simulator in-memory audit sink (INC-2-API §4.12, §5.1; SR-6; ADR 0005)."""

import pytest

from teecustody.audit import (
    AppendResult,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
)
from teecustody_sim.backends import InMemoryAuditSink

TS = 1_800_000_000_000
EVENT_KEY = AuditKey(AuditClass.EVENT, "evt1")
ALERT_KEY = AuditKey(AuditClass.ALERT, "00" * 16 + "/PREKEY_BURN_HIGH")
AGGREGATE_KEY = AuditKey(AuditClass.AGGREGATE, "1799999940000/REQUEST_INVALID/0011223344556677")


def _aggregate(count: int) -> AuditRecord:
    return AuditRecord(
        outcome="REQUEST_INVALID",
        ts=TS,
        interval_start=TS - 60_000,
        interval_end=TS,
        count=count,
    )


def test_a_valid_record_is_created() -> None:
    sink = InMemoryAuditSink()
    record = AuditRecord(outcome="FIRST", ts=TS)

    assert sink.append(EVENT_KEY, record) is AppendResult.CREATED
    assert sink.records() == [(EVENT_KEY, record)]


def test_the_same_key_again_is_already_exists_and_the_original_is_kept() -> None:
    sink = InMemoryAuditSink()
    sink.append(EVENT_KEY, AuditRecord(outcome="FIRST", ts=TS))

    result = sink.append(EVENT_KEY, AuditRecord(outcome="SECOND", ts=TS + 1))

    assert result is AppendResult.ALREADY_EXISTS
    assert sink.records() == [(EVENT_KEY, AuditRecord(outcome="FIRST", ts=TS))]


def test_the_same_id_in_another_class_is_a_different_object() -> None:
    sink = InMemoryAuditSink()
    sink.append(AuditKey(AuditClass.EVENT, "same"), AuditRecord(outcome="A", ts=TS))

    result = sink.append(AuditKey(AuditClass.RELEASE, "same"), AuditRecord(outcome="B", ts=TS))

    assert result is AppendResult.CREATED
    assert len(sink.records()) == 2


def test_an_invalid_record_is_refused_and_not_stored() -> None:
    sink = InMemoryAuditSink()

    with pytest.raises(AuditError) as caught:
        sink.append(ALERT_KEY, AuditRecord(outcome="PREKEY_BURN_HIGH", ts=TS, count=3))

    assert caught.value.code is AuditErrorCode.INVALID_ARGUMENT
    assert sink.records() == []


def test_an_invalid_record_under_an_existing_key_is_refused_not_reported_as_existing() -> None:
    sink = InMemoryAuditSink()
    sink.append(ALERT_KEY, AuditRecord(outcome="PREKEY_BURN_HIGH", ts=TS))

    with pytest.raises(AuditError) as caught:
        sink.append(ALERT_KEY, AuditRecord(outcome="PREKEY_BURN_HIGH", ts=TS, count=3))

    assert caught.value.code is AuditErrorCode.INVALID_ARGUMENT


def test_fail_next_two_makes_exactly_two_appends_unavailable_without_storing() -> None:
    sink = InMemoryAuditSink()
    sink.fail_next(2)

    codes = []
    for _ in range(2):
        with pytest.raises(AuditError) as caught:
            sink.append(AGGREGATE_KEY, _aggregate(1))
        codes.append(caught.value.code)
    assert sink.records() == []
    third = sink.append(AGGREGATE_KEY, _aggregate(1))

    assert codes == [AuditErrorCode.UNAVAILABLE, AuditErrorCode.UNAVAILABLE]
    assert third is AppendResult.CREATED
    assert sink.records() == [(AGGREGATE_KEY, _aggregate(1))]


def test_fail_next_raises_the_requested_code() -> None:
    sink = InMemoryAuditSink()
    sink.fail_next(1, AuditErrorCode.INVALID_ARGUMENT)

    with pytest.raises(AuditError) as caught:
        sink.append(EVENT_KEY, AuditRecord(outcome="X", ts=TS))

    assert caught.value.code is AuditErrorCode.INVALID_ARGUMENT
    assert sink.append(EVENT_KEY, AuditRecord(outcome="X", ts=TS)) is AppendResult.CREATED


def test_fail_next_zero_injects_nothing() -> None:
    sink = InMemoryAuditSink()
    sink.fail_next(0)

    assert sink.append(EVENT_KEY, AuditRecord(outcome="X", ts=TS)) is AppendResult.CREATED


def test_records_filters_by_class_in_insertion_order() -> None:
    sink = InMemoryAuditSink()
    second_event = AuditKey(AuditClass.EVENT, "evt0")
    sink.append(EVENT_KEY, AuditRecord(outcome="E1", ts=TS))
    sink.append(AGGREGATE_KEY, _aggregate(2))
    sink.append(second_event, AuditRecord(outcome="E2", ts=TS))

    events = sink.records(AuditClass.EVENT)

    assert [(k, r.outcome) for k, r in events] == [(EVENT_KEY, "E1"), (second_event, "E2")]
    assert sink.records(AuditClass.AGGREGATE) == [(AGGREGATE_KEY, _aggregate(2))]
    assert sink.records(AuditClass.ALERT) == []
    assert [k for k, _ in sink.records()] == [EVENT_KEY, AGGREGATE_KEY, second_event]


def test_records_returns_a_copy() -> None:
    sink = InMemoryAuditSink()
    sink.append(EVENT_KEY, AuditRecord(outcome="E1", ts=TS))

    sink.records().clear()
    sink.records(AuditClass.EVENT).clear()

    assert len(sink.records()) == 1


@pytest.mark.parametrize("bad", [-1, True, 1.0, "2", None])
def test_fail_next_with_a_non_count_is_refused(bad: object) -> None:
    sink = InMemoryAuditSink()

    with pytest.raises(ValueError, match=r"^FAIL_NEXT$"):
        sink.fail_next(bad)  # type: ignore[arg-type]

    assert sink.append(EVENT_KEY, AuditRecord(outcome="X", ts=TS)) is AppendResult.CREATED
