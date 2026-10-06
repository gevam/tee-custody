"""Contract: Queue port (WorkloadQueue + RelayQueue) and AuditSink port semantics against the
simulator adapters (FR-5, SR-3, SR-6; INC-2-API §4.11, §4.12, §5.1; D-012, D2-12).

Expected red until T-11 and T-24 merge (docs/tasks/INC-2/WAVES.md).
"""

from __future__ import annotations

import pytest
from tc_channel_support import FakeClock

from teecustody.audit import (
    AppendResult,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    validate_audit,
)
from teecustody.queue import QueueError, QueueErrorCode
from teecustody_sim.backends import InMemoryAuditSink, InMemoryQueue

INSTANCE = "a1" * 16
CLIENT = "c1" * 16


def _queue(clock: FakeClock) -> InMemoryQueue:
    return InMemoryQueue(ack_deadline_s=30.0, clock=clock)


def test_bundles_are_listed_until_expiry_and_withdrawn() -> None:
    clock = FakeClock()
    queue = _queue(clock)
    queue.publish_bundle(INSTANCE, b"bundle", int(clock()) + 60)

    listed = queue.list_bundles(16)

    assert [(b.instance_id, b.bundle) for b in listed] == [(INSTANCE, b"bundle")]
    clock.now += 61
    assert queue.list_bundles(16) == []
    queue.withdraw_bundle(INSTANCE)
    queue.withdraw_bundle(INSTANCE)


def test_request_needs_a_live_bundle_and_is_redelivered_until_acked() -> None:
    clock = FakeClock()
    queue = _queue(clock)
    with pytest.raises(QueueError) as caught:
        queue.publish_request(INSTANCE, "f0" * 16, b"req")
    assert caught.value.code is QueueErrorCode.NOT_FOUND

    queue.publish_bundle(INSTANCE, b"bundle", int(clock()) + 600)
    queue.publish_request(INSTANCE, "f0" * 16, b"req")
    [message] = queue.pull_requests(INSTANCE, 32, 0.0)
    assert (message.request_id, message.body) == ("f0" * 16, b"req")
    assert queue.pull_requests(INSTANCE, 32, 0.0) == []

    clock.now += 31
    [again] = queue.pull_requests(INSTANCE, 32, 0.0)
    assert again.message_id == message.message_id
    queue.ack(again.message_id)
    clock.now += 31
    assert queue.pull_requests(INSTANCE, 32, 0.0) == []
    queue.ack("0" * 32)


def test_responses_are_paged_per_client_route_only() -> None:
    queue = _queue(FakeClock())
    for index in range(3):
        queue.publish_response(CLIENT, f"{index:032x}", bytes([index]))

    first = queue.pull_responses(CLIENT, None, 2)
    second = queue.pull_responses(CLIENT, first.next, 2)

    assert [r.body for r in first.responses] == [b"\x00", b"\x01"]
    assert [r.body for r in second.responses] == [b"\x02"]
    assert queue.pull_responses("d1" * 16, None, 2).responses == ()


@pytest.mark.parametrize("bad", ["A1" * 16, "a1" * 15 + "a", "a1" * 16 + "\n", "a1" * 17])
def test_identifiers_are_full_matched(bad: str) -> None:
    queue = _queue(FakeClock())
    with pytest.raises(QueueError) as caught:
        queue.pull_responses(bad, None, 2)
    assert caught.value.code is QueueErrorCode.INVALID_ARGUMENT


def test_cursor_beyond_the_last_issued_is_invalid() -> None:
    queue = _queue(FakeClock())
    queue.publish_response(CLIENT, "0" * 32, b"x")
    with pytest.raises(QueueError) as caught:
        queue.pull_responses(CLIENT, "99", 2)
    assert caught.value.code is QueueErrorCode.INVALID_ARGUMENT


def _aggregate(count: int | None) -> AuditRecord:
    return AuditRecord(
        outcome="REQUEST_INVALID",
        ts=1_800_000_000_000,
        interval_start=1_799_999_940_000,
        interval_end=1_800_000_000_000,
        count=count,
    )


def test_audit_sink_is_create_only() -> None:
    sink = InMemoryAuditSink()
    key = AuditKey(AuditClass.AGGREGATE, "1799999940000/REQUEST_INVALID/0011223344556677")

    assert sink.append(key, _aggregate(3)) is AppendResult.CREATED
    assert sink.append(key, _aggregate(4)) is AppendResult.ALREADY_EXISTS
    assert [record.count for _, record in sink.records(AuditClass.AGGREGATE)] == [3]


def test_count_is_only_allowed_on_aggregates() -> None:
    alert = AuditRecord(outcome="PREKEY_BURN_HIGH", ts=1, count=5)
    with pytest.raises(AuditError) as caught:
        validate_audit(AuditKey(AuditClass.ALERT, "00112233445566778899aabbccddeeff/X"), alert)
    assert caught.value.code is AuditErrorCode.INVALID_ARGUMENT
    with pytest.raises(AuditError):
        validate_audit(AuditKey(AuditClass.AGGREGATE, "1/REQUEST_INVALID/00"), _aggregate(None))


def test_sink_fault_injection_raises_unavailable() -> None:
    sink = InMemoryAuditSink()
    sink.fail_next(1)
    key = AuditKey(AuditClass.AGGREGATE, "1799999940000/REQUEST_INVALID/0011223344556677")
    with pytest.raises(AuditError) as caught:
        sink.append(key, _aggregate(1))
    assert caught.value.code is AuditErrorCode.UNAVAILABLE
    assert sink.append(key, _aggregate(1)) is AppendResult.CREATED
