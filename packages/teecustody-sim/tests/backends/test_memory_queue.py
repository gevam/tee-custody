"""T-24: the simulator in-memory queue (INC-2-API §4.11, §5.1; spec §9, §15.2; SR-3, SR-4)."""

import threading
import time
from collections.abc import Callable

import pytest

from teecustody.queue import (
    PublishedBundle,
    PublishedResponse,
    QueueError,
    QueueErrorCode,
    QueueMessage,
    ResponsePage,
)
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


# ---------------------------------------------------------------- criterion 5: response paging
CLIENT = "c1" * 16
OTHER_CLIENT = "d1" * 16


def _five_responses(queue: InMemoryQueue) -> None:
    for index in range(5):
        queue.publish_response(CLIENT, f"{index:032x}", bytes([index]))


def test_responses_are_paged_in_order_with_decimal_cursors() -> None:
    queue = _queue(FakeClock())
    _five_responses(queue)

    first = queue.pull_responses(CLIENT, None, 2)
    second = queue.pull_responses(CLIENT, first.next, 2)
    third = queue.pull_responses(CLIENT, second.next, 2)
    empty = queue.pull_responses(CLIENT, third.next, 2)

    assert first == ResponsePage(
        (PublishedResponse("0" * 32, b"\x00"), PublishedResponse(f"{1:032x}", b"\x01")), "2"
    )
    assert [r.body for r in second.responses] == [b"\x02", b"\x03"]
    assert second.next == "4"
    assert [r.body for r in third.responses] == [b"\x04"]
    assert third.next == "5"
    assert empty == ResponsePage((), None)


def test_after_zero_returns_every_response() -> None:
    queue = _queue(FakeClock())
    _five_responses(queue)

    page = queue.pull_responses(CLIENT, "0", 10)

    assert [r.body for r in page.responses] == [bytes([i]) for i in range(5)]
    assert page.next == "5"


@pytest.mark.parametrize("after", ["x", "-1", "6", "+1", "1.0", " 1", "01", "", "1" * 21])
def test_malformed_or_future_cursor_is_invalid_argument(after: str) -> None:
    queue = _queue(FakeClock())
    _five_responses(queue)

    with pytest.raises(QueueError) as caught:
        queue.pull_responses(CLIENT, after, 2)

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT


def test_another_clients_route_returns_an_empty_page() -> None:
    queue = _queue(FakeClock())
    _five_responses(queue)

    assert queue.pull_responses(OTHER_CLIENT, None, 10) == ResponsePage((), None)


def test_each_route_has_its_own_increasing_sequence() -> None:
    queue = _queue(FakeClock())
    queue.publish_response(CLIENT, "01" * 16, b"c1")
    queue.publish_response(OTHER_CLIENT, "02" * 16, b"o1")
    queue.publish_response(CLIENT, "03" * 16, b"c2")
    queue.publish_response(OTHER_CLIENT, "04" * 16, b"o2")

    mine = queue.pull_responses(CLIENT, None, 1)
    rest = queue.pull_responses(CLIENT, mine.next, 10)
    other = queue.pull_responses(OTHER_CLIENT, None, 10)

    assert [r.body for r in mine.responses + rest.responses] == [b"c1", b"c2"]
    assert int(mine.next or "") < int(rest.next or "")
    assert [r.body for r in other.responses] == [b"o1", b"o2"]


# ---------------------------------------------------------------- criterion 6: retention and depth
def test_requests_older_than_retention_are_dropped_even_if_unacked() -> None:
    clock = FakeClock()
    queue = _queue(clock, request_retention_s=300.0, ack_deadline_s=1.0)
    queue.publish_bundle(IID_A, b"a", int(START) + 3600)
    queue.publish_request(IID_A, "01" * 16, b"old")
    clock.now = START + 100
    queue.publish_request(IID_A, "02" * 16, b"new")

    clock.now = START + 299.999
    before = queue.pull_requests(IID_A, 10, 0.0)
    clock.now = START + 301
    after = queue.pull_requests(IID_A, 10, 0.0)
    clock.now = START + 401
    last = queue.pull_requests(IID_A, 10, 0.0)

    assert [m.body for m in before] == [b"old", b"new"]
    assert [m.body for m in after] == [b"new"]
    assert last == []


def test_responses_older_than_retention_are_dropped() -> None:
    clock = FakeClock()
    queue = _queue(clock, response_retention_s=300.0)
    queue.publish_response(CLIENT, "01" * 16, b"old")
    clock.now = START + 100
    queue.publish_response(CLIENT, "02" * 16, b"new")

    clock.now = START + 300
    page = queue.pull_responses(CLIENT, None, 10)

    assert page == ResponsePage((PublishedResponse("02" * 16, b"new"),), "2")


def test_full_request_topic_is_unavailable_until_it_drains() -> None:
    queue = _queue(FakeClock(), max_topic_depth=2)
    queue.publish_bundle(IID_A, b"a", int(START) + 600)
    queue.publish_bundle(IID_B, b"b", int(START) + 600)
    queue.publish_request(IID_A, "01" * 16, b"1")
    queue.publish_request(IID_B, "02" * 16, b"2")

    with pytest.raises(QueueError) as caught:
        queue.publish_request(IID_A, "03" * 16, b"3")
    [message] = queue.pull_requests(IID_B, 10, 0.0)
    queue.ack(message.message_id)
    queue.publish_request(IID_A, "03" * 16, b"3")

    assert _code(caught) is QueueErrorCode.UNAVAILABLE
    assert [m.body for m in queue.pull_requests(IID_A, 10, 0.0)] == [b"1", b"3"]


def test_full_response_topic_is_unavailable_until_retention_drains_it() -> None:
    clock = FakeClock()
    queue = _queue(clock, max_topic_depth=2, response_retention_s=300.0)
    queue.publish_response(CLIENT, "01" * 16, b"1")
    queue.publish_response(OTHER_CLIENT, "02" * 16, b"2")

    with pytest.raises(QueueError) as caught:
        queue.publish_response(CLIENT, "03" * 16, b"3")
    clock.now = START + 300
    queue.publish_response(CLIENT, "03" * 16, b"3")

    assert _code(caught) is QueueErrorCode.UNAVAILABLE
    assert [r.body for r in queue.pull_responses(CLIENT, None, 10).responses] == [b"3"]


def test_bundles_beyond_max_bundles_live_instances_are_unavailable() -> None:
    clock = FakeClock()
    queue = _queue(clock, max_bundles=2)
    queue.publish_bundle(IID_A, b"a", int(START) + 10)
    queue.publish_bundle(IID_B, b"b", int(START) + 600)

    with pytest.raises(QueueError) as caught:
        queue.publish_bundle("cc" * 16, b"c", int(START) + 600)
    queue.publish_bundle(IID_B, b"b2", int(START) + 600)
    clock.now = START + 10
    queue.publish_bundle("cc" * 16, b"c", int(START) + 600)

    assert _code(caught) is QueueErrorCode.UNAVAILABLE
    assert [b.bundle for b in queue.list_bundles(10)] == [b"b2", b"c"]


def test_bundle_already_expired_at_publish_is_invalid_argument() -> None:
    queue = _queue(FakeClock(START + 0.5))

    with pytest.raises(QueueError) as caught:
        queue.publish_bundle(IID_A, b"a", int(START))

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT
    assert queue.list_bundles(10) == []


def test_a_drained_route_is_released_and_its_stale_cursor_still_sees_new_responses() -> None:
    clock = FakeClock()
    queue = _queue(clock, response_retention_s=300.0)
    _five_responses(queue)
    cursor = queue.pull_responses(CLIENT, None, 10).next

    clock.now = START + 300
    assert queue.pull_responses(CLIENT, cursor, 10) == ResponsePage((), None)
    assert queue._routes == {}  # SR-4: no per-client state outlives its responses
    queue.publish_response(CLIENT, "06" * 16, b"after-drain")
    page = queue.pull_responses(CLIENT, cursor, 10)

    assert [r.body for r in page.responses] == [b"after-drain"]
    assert int(page.next or "") > int(cursor or "")


def test_cursor_of_a_route_without_responses_is_bounded_by_every_sequence_issued() -> None:
    queue = _queue(FakeClock())
    queue.publish_response(CLIENT, "01" * 16, b"x")

    assert queue.pull_responses(OTHER_CLIENT, "1", 10) == ResponsePage((), None)
    with pytest.raises(QueueError) as caught:
        queue.pull_responses(OTHER_CLIENT, "2", 10)
    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT


# ---------------------------------------------------------------- criterion 7: identifiers (R-7)
GOOD = "ab" * 16
BAD_IDS = ["AB" * 16, "ab" * 15 + "a", "ab" * 16 + "a", "ab" * 16 + "\n", "", "ab" * 15 + "g0"]
BAD_ID_NAMES = ["uppercase", "31-chars", "33-chars", "trailing-newline", "empty", "non-hex"]

ID_CALLS: dict[str, Callable[[InMemoryQueue, str], object]] = {
    "publish_bundle.instance_id": lambda q, v: q.publish_bundle(v, b"b", int(START) + 60),
    "pull_requests.instance_id": lambda q, v: q.pull_requests(v, 1, 0.0),
    "ack.message_id": lambda q, v: q.ack(v),
    "publish_response.client_id": lambda q, v: q.publish_response(v, GOOD, b"r"),
    "publish_response.request_id": lambda q, v: q.publish_response(GOOD, v, b"r"),
    "withdraw_bundle.instance_id": lambda q, v: q.withdraw_bundle(v),
    "publish_request.instance_id": lambda q, v: q.publish_request(v, GOOD, b"r"),
    "publish_request.request_id": lambda q, v: q.publish_request(GOOD, v, b"r"),
    "pull_responses.client_id": lambda q, v: q.pull_responses(v, None, 1),
}


@pytest.mark.parametrize("bad", BAD_IDS, ids=BAD_ID_NAMES)
@pytest.mark.parametrize("call", list(ID_CALLS))
def test_every_id_argument_is_full_matched(call: str, bad: str) -> None:
    queue = _queue(FakeClock())
    queue.publish_bundle(GOOD, b"live", int(START) + 600)

    with pytest.raises(QueueError) as caught:
        ID_CALLS[call](queue, bad)

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT
    assert queue.list_bundles(10) == [PublishedBundle(GOOD, b"live")]
    assert queue.pull_requests(GOOD, 10, 0.0) == []
    assert queue.pull_responses(GOOD, None, 10) == ResponsePage((), None)


@pytest.mark.parametrize("call", list(ID_CALLS))
def test_a_non_string_id_is_invalid_argument(call: str) -> None:
    queue = _queue(FakeClock())

    with pytest.raises(QueueError) as caught:
        ID_CALLS[call](queue, b"ab" * 16)  # type: ignore[arg-type]

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("namespace", ["sim", "a", "dev-1", "a" + "b" * 31])
def test_valid_namespaces_are_accepted(namespace: str) -> None:
    InMemoryQueue(namespace=namespace)


@pytest.mark.parametrize(
    "namespace", ["", "Sim", "1sim", "-sim", "sim_1", "a" + "b" * 32, "sim\n", " sim"]
)
def test_invalid_namespace_is_refused_at_construction(namespace: str) -> None:
    with pytest.raises(ValueError, match=r"^NAMESPACE$"):
        InMemoryQueue(namespace=namespace)


# ---------------------------------------------------------------- limits (R-7)
BAD_COUNTS: list[object] = [0, 1001, -1, True, 1.0, "1", None]
LIMIT_CALLS: dict[str, Callable[[InMemoryQueue, object], object]] = {
    "pull_requests.max_messages": lambda q, v: q.pull_requests(GOOD, v, 0.0),  # type: ignore[arg-type]
    "pull_responses.max_messages": lambda q, v: q.pull_responses(GOOD, None, v),  # type: ignore[arg-type]
    "list_bundles.max_bundles": lambda q, v: q.list_bundles(v),  # type: ignore[arg-type]
}


@pytest.mark.parametrize("bad", BAD_COUNTS, ids=repr)
@pytest.mark.parametrize("call", list(LIMIT_CALLS))
def test_counts_outside_one_to_a_thousand_are_invalid_argument(call: str, bad: object) -> None:
    queue = _queue(FakeClock())

    with pytest.raises(QueueError) as caught:
        LIMIT_CALLS[call](queue, bad)

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize("good", [1, 1000])
@pytest.mark.parametrize("call", list(LIMIT_CALLS))
def test_counts_at_the_bounds_are_accepted(call: str, good: int) -> None:
    LIMIT_CALLS[call](_queue(FakeClock()), good)


@pytest.mark.parametrize("bad", [-0.001, 30.001, float("nan"), float("inf"), True, "1", None])
def test_wait_outside_zero_to_thirty_seconds_is_invalid_argument(bad: object) -> None:
    queue = _queue(FakeClock())

    with pytest.raises(QueueError) as caught:
        queue.pull_requests(GOOD, 1, bad)  # type: ignore[arg-type]

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT


def test_wait_of_zero_and_integer_seconds_are_accepted() -> None:
    queue = _queue(FakeClock())
    queue.publish_bundle(GOOD, b"b", int(START) + 600)
    queue.publish_request(GOOD, "01" * 16, b"r")

    assert queue.pull_requests(GOOD, 1, 0) != []
    clock_free = InMemoryQueue()
    assert clock_free.pull_requests(GOOD, 1, 0.0) == []


@pytest.mark.parametrize("bad", [True, float(START + 60), "1900000000", None])
def test_non_integer_bundle_expiry_is_invalid_argument(bad: object) -> None:
    queue = _queue(FakeClock())

    with pytest.raises(QueueError) as caught:
        queue.publish_bundle(GOOD, b"b", bad)  # type: ignore[arg-type]

    assert _code(caught) is QueueErrorCode.INVALID_ARGUMENT
