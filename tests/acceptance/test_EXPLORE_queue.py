"""QA exploratory (INC-2 phase 2): the in-memory queue adapter at its public port (E-4), hostile arguments."""

import time

import pytest

from teecustody.queue import QueueError
from teecustody_sim.backends import InMemoryQueue

IID = "ab" * 16
RID = "cd" * 16


def _live() -> InMemoryQueue:
    q = InMemoryQueue()
    q.publish_bundle(IID, b"bundle", int(time.time()) + 600)
    return q


@pytest.mark.parametrize(
    "iid", ["", "AB" * 16, "ab" * 15, "ab" * 17, "zz" * 16, IID + "\n", "ab" * 16 + "\x00", "%0A"]
)
def test_publish_request_rejects_malformed_instance_ids(iid: str) -> None:
    with pytest.raises(QueueError):
        _live().publish_request(iid, RID, b"x")


@pytest.mark.parametrize("rid", ["", "CD" * 16, "cd" * 15, RID + "\n", None, 5])
def test_publish_request_rejects_malformed_request_ids(rid: object) -> None:
    with pytest.raises(QueueError):
        _live().publish_request(IID, rid, b"x")  # type: ignore[arg-type]


def test_unknown_instance_is_not_found_and_message_types_are_checked() -> None:
    q = _live()
    with pytest.raises(QueueError) as e:
        q.publish_request("00" * 16, RID, b"x")
    assert str(e.value.code) == "NOT_FOUND"
    for body in ("str", None, 5, bytearray(b"x")):
        try:
            q.publish_request(IID, RID, body)  # type: ignore[arg-type]
        except QueueError:
            pass


@pytest.mark.parametrize("after", ["", "a" * 129, "a b", "a\n", "../x", "%", "é"])
def test_pull_responses_rejects_hostile_cursors(after: str) -> None:
    with pytest.raises(QueueError):
        InMemoryQueue().pull_responses(IID, after, 10)


@pytest.mark.parametrize("n", [0, -1, 10**9, True, 1.5, None])
def test_pull_limits_are_validated(n: object) -> None:
    q = _live()
    with pytest.raises((QueueError, TypeError, ValueError)):
        q.pull_responses(IID, None, n)  # type: ignore[arg-type]
    with pytest.raises((QueueError, TypeError, ValueError)):
        q.list_bundles(n)  # type: ignore[arg-type]


def test_capacity_is_bounded_and_fails_unavailable_not_by_growing() -> None:
    q = InMemoryQueue(max_topic_depth=5)
    q.publish_bundle(IID, b"b", int(time.time()) + 600)
    ok = 0
    codes = set()
    for i in range(50):
        try:
            q.publish_request(IID, f"{i:032x}", b"x" * 1000)
            ok += 1
        except QueueError as e:
            codes.add(str(e.code))
    assert ok == 5 and codes == {"UNAVAILABLE"}


def test_unknown_ack_and_double_ack_are_noops_and_withdraw_is_idempotent() -> None:
    q = _live()
    q.ack("ee" * 16)
    with pytest.raises(QueueError):  # malformed (not merely unknown) id is INVALID_ARGUMENT
        q.ack("not-an-id")
    q.withdraw_bundle(IID)
    q.withdraw_bundle(IID)
    q.withdraw_bundle("00" * 16)
    assert q.list_bundles(16) == []


def test_expired_bundle_is_not_listed_and_not_a_publish_target() -> None:
    q = InMemoryQueue()
    with pytest.raises(QueueError):  # an already-expired bundle is refused at publish
        q.publish_bundle(IID, b"b", int(time.time()) - 1)
    assert q.list_bundles(16) == []
    with pytest.raises(QueueError):
        q.publish_request(IID, RID, b"x")


def test_response_page_order_and_cursor_progress_with_many_responses() -> None:
    q = _live()
    for i in range(100):
        q.publish_response(IID, f"{i:032x}", b"r%d" % i)
    seen, after = [], None
    for _ in range(100):
        page = q.pull_responses(IID, after, 32)
        seen += [r.request_id for r in page.responses]
        if page.next is None:
            break
        after = page.next
    assert seen == [f"{i:032x}" for i in range(100)]
