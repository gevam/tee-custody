"""T-24: the simulator's in-memory queue (INC-2-API §4.11, §5.1; spec §9, §15.2 item 5; SR-3, SR-4)."""

import threading
import time
from collections.abc import Callable

import pytest

from teecustody.queue import PublishedBundle, QueueError, QueueErrorCode, QueueMessage
from teecustody_sim.backends import InMemoryQueue

START = 1_800_000_000.0
IID_A = "aa" * 16
IID_B = "bb" * 16


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _queue(clock: FakeClock, **kwargs: object) -> InMemoryQueue:
    return InMemoryQueue(clock=clock, **kwargs)  # type: ignore[arg-type]


def _code(caught: pytest.ExceptionInfo[QueueError]) -> QueueErrorCode:
    return caught.value.code


# ---------------------------------------------------------------- criterion 1: bundles
def test_bundles_are_listed_until_expiry_sorted_by_instance_id() -> None:
    clock = FakeClock()
    queue = _queue(clock)
    queue.publish_bundle(IID_B, b"bundle-b", int(START) + 100)
    queue.publish_bundle(IID_A, b"bundle-a", int(START) + 50)

    assert queue.list_bundles(10) == [
        PublishedBundle(IID_A, b"bundle-a"),
        PublishedBundle(IID_B, b"bundle-b"),
    ]
    clock.now = START + 49.999
    assert [b.instance_id for b in queue.list_bundles(10)] == [IID_A, IID_B]
    clock.now = START + 50
    assert queue.list_bundles(10) == [PublishedBundle(IID_B, b"bundle-b")]


def test_list_bundles_returns_at_most_max_bundles() -> None:
    queue = _queue(FakeClock())
    queue.publish_bundle(IID_B, b"b", int(START) + 100)
    queue.publish_bundle(IID_A, b"a", int(START) + 100)

    assert queue.list_bundles(1) == [PublishedBundle(IID_A, b"a")]


def test_republishing_replaces_the_instance_bundle() -> None:
    queue = _queue(FakeClock())
    queue.publish_bundle(IID_A, b"old", int(START) + 100)
    queue.publish_bundle(IID_A, b"new", int(START) + 200)

    assert queue.list_bundles(10) == [PublishedBundle(IID_A, b"new")]


def test_withdraw_bundle_removes_it_and_is_idempotent() -> None:
    queue = _queue(FakeClock())
    queue.publish_bundle(IID_A, b"a", int(START) + 100)
    queue.publish_bundle(IID_B, b"b", int(START) + 100)

    queue.withdraw_bundle(IID_A)
    queue.withdraw_bundle(IID_A)

    assert queue.list_bundles(10) == [PublishedBundle(IID_B, b"b")]


# ---------------------------------------------------------------- criterion 2: live bundle required
def test_publish_request_without_a_live_bundle_is_not_found() -> None:
    clock = FakeClock()
    queue = _queue(clock)
    with pytest.raises(QueueError) as never:
        queue.publish_request(IID_A, "01" * 16, b"req")
    queue.publish_bundle(IID_A, b"a", int(START) + 10)
    clock.now = START + 10
    with pytest.raises(QueueError) as expired:
        queue.publish_request(IID_A, "01" * 16, b"req")

    assert _code(never) is QueueErrorCode.NOT_FOUND
    assert _code(expired) is QueueErrorCode.NOT_FOUND


# ---------------------------------------------------------------- criterion 3: delivery and ack
def _seq_rng() -> Callable[[int], bytes]:
    counter = iter(range(1, 1_000_000))

    def rng(n: int) -> bytes:
        return next(counter).to_bytes(n, "big")

    return rng


def test_pulled_request_carries_message_id_relay_id_body_and_publish_time() -> None:
    clock = FakeClock()
    queue = _queue(clock, rng=_seq_rng())
    queue.publish_bundle(IID_A, b"a", int(START) + 600)
    message_id = queue.publish_request(IID_A, "01" * 16, b"req")

    [message] = queue.pull_requests(IID_A, 10, 0.0)

    assert message_id == "00" * 15 + "01"
    assert message == QueueMessage(message_id, "01" * 16, b"req", START)


def test_unacked_request_reappears_after_the_ack_deadline() -> None:
    clock = FakeClock()
    queue = _queue(clock, ack_deadline_s=30.0)
    queue.publish_bundle(IID_A, b"a", int(START) + 600)
    queue.publish_request(IID_A, "01" * 16, b"req")
    [first] = queue.pull_requests(IID_A, 10, 0.0)

    clock.now = START + 29.999
    hidden = queue.pull_requests(IID_A, 10, 0.0)
    clock.now = START + 30
    [again] = queue.pull_requests(IID_A, 10, 0.0)

    assert hidden == []
    assert again == first


def test_acked_request_never_reappears_and_unknown_ack_is_a_no_op() -> None:
    clock = FakeClock()
    queue = _queue(clock, ack_deadline_s=30.0)
    queue.publish_bundle(IID_A, b"a", int(START) + 600)
    queue.publish_request(IID_A, "01" * 16, b"one")
    queue.publish_request(IID_A, "02" * 16, b"two")
    first, second = queue.pull_requests(IID_A, 10, 0.0)

    queue.ack(first.message_id)
    queue.ack(first.message_id)
    queue.ack("ff" * 16)
    clock.now = START + 31

    assert queue.pull_requests(IID_A, 10, 0.0) == [second]


def test_pull_returns_oldest_first_up_to_max_messages_for_the_named_instance_only() -> None:
    clock = FakeClock()
    queue = _queue(clock)
    queue.publish_bundle(IID_A, b"a", int(START) + 600)
    queue.publish_bundle(IID_B, b"b", int(START) + 600)
    queue.publish_request(IID_A, "01" * 16, b"a1")
    queue.publish_request(IID_B, "02" * 16, b"b1")
    queue.publish_request(IID_A, "03" * 16, b"a2")
    queue.publish_request(IID_A, "04" * 16, b"a3")

    first = queue.pull_requests(IID_A, 2, 0.0)
    rest = queue.pull_requests(IID_A, 2, 0.0)

    assert [m.body for m in first] == [b"a1", b"a2"]
    assert [m.body for m in rest] == [b"a3"]
    assert [m.body for m in queue.pull_requests(IID_B, 10, 0.0)] == [b"b1"]


# ---------------------------------------------------------------- criterion 4: blocking pull
def test_pull_on_an_empty_topic_blocks_for_wait_s_then_returns_empty() -> None:
    queue = InMemoryQueue()

    started = time.monotonic()
    pulled = queue.pull_requests(IID_A, 10, 0.2)
    elapsed = time.monotonic() - started

    assert pulled == []
    assert 0.2 <= elapsed < 1.0


def test_a_publish_from_another_thread_wakes_a_blocked_pull_early() -> None:
    queue = InMemoryQueue()
    queue.publish_bundle(IID_A, b"a", int(time.time()) + 600)
    publisher = threading.Timer(0.05, queue.publish_request, (IID_A, "01" * 16, b"late"))

    started = time.monotonic()
    publisher.start()
    pulled = queue.pull_requests(IID_A, 10, 5.0)
    elapsed = time.monotonic() - started
    publisher.join()

    assert [m.body for m in pulled] == [b"late"]
    assert elapsed < 2.0
