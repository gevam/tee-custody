"""T-24: the simulator's in-memory queue (INC-2-API §4.11, §5.1; spec §9, §15.2 item 5; SR-3, SR-4)."""

import pytest

from teecustody.queue import PublishedBundle, QueueError, QueueErrorCode
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
