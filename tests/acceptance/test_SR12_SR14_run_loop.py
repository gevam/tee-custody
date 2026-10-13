"""Run-loop behaviours for INC-2: publish retries, pre-key burn alert, bundle upkeep (SR-12, SR-14).

Owning tasks: T-29 (run loop), T-28 (server), T-22 (pre-keys, bundle), T-24 (queue, sinks),
T-12 (audit). Expected failure on trunk: NotImplementedError('T-29') at `RunLoop(...)`.
"""

from typing import Any

from acc_channel import (
    CLIENT_ID,
    prekey_signature_valid,
    read_frame_result,
    read_open_result,
    seal_frame,
    uncbor,
)
from acc_runloop import RunWorld, make_run_world
from acc_support import RunningSim
from teecustody.audit import AuditClass
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.queue import QueueError, QueueErrorCode


class FailOnePublish:
    """WorkloadQueue wrapper: the Nth `publish_response` raises UNAVAILABLE; all bodies are kept."""

    def __init__(self, inner: Any, fail_attempt: int) -> None:
        self.inner, self.fail_attempt = inner, fail_attempt
        self.attempts: list[bytes] = []

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        self.inner.publish_bundle(instance_id, bundle, expires_at)

    def pull_requests(self, instance_id: str, max_messages: int, wait_s: float) -> Any:
        return self.inner.pull_requests(instance_id, max_messages, wait_s)

    def ack(self, message_id: str) -> None:
        self.inner.ack(message_id)

    def withdraw_bundle(self, instance_id: str) -> None:
        self.inner.withdraw_bundle(instance_id)

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        self.attempts.append(body)
        if len(self.attempts) == self.fail_attempt:
            raise QueueError(QueueErrorCode.UNAVAILABLE)
        self.inner.publish_response(client_id, request_id, body)


def _open_and_read(world: RunWorld, route: str = CLIENT_ID) -> tuple[Any, bytes]:
    sent = world.open_session(route=route)
    world.post(sent.body)
    world.tick()
    answers = [b for _r, b in world.responses(route)]
    opened = read_open_result(answers[-1], sent.t2c)
    assert opened.ok and opened.session_id is not None
    return sent, opened.session_id


def test_SR14_a_failed_publish_is_retried_with_identical_bytes_and_never_resealed(
    running_sim: RunningSim,
) -> None:
    # Given a run loop whose second response publish (the first frame's answer) fails once
    flaky: list[FailOnePublish] = []

    def wrap(raw: Any) -> FailOnePublish:
        flaky.append(FailOnePublish(raw, fail_attempt=2))
        return flaky[-1]

    world = make_run_world(running_sim, queue=wrap)
    sent, sid = _open_and_read(world)
    # When two requests are sent, with ticks in between for the retry
    for seq in (0, 1):
        world.post(seal_frame(sent.c2t, sid, seq, "test.echo", {"n": seq}))
        world.tick(3)
    # Then no result was ever sealed twice: every sequence number maps to exactly one body, so a
    # retry (permitted once) re-sent identical bytes, and the seqs used are 0 (open), 1 and 2
    by_seq: dict[int, set[bytes]] = {}
    for body in flaky[0].attempts:
        envelope = uncbor(body)
        by_seq.setdefault(uncbor(envelope["aad"])["seq"], set()).add(body)
    assert all(len(bodies) == 1 for bodies in by_seq.values())
    assert sorted(by_seq) == [0, 1, 2]
    # And the client never sees a duplicate or out-of-order sequence number
    delivered = [b for _r, b in world.responses(CLIENT_ID)][1:]
    seqs = [read_frame_result(b, sent.t2c).seq for b in delivered]
    assert seqs == sorted(set(seqs)) and set(seqs) <= {1, 2}
    # And each request ran exactly once
    assert [c[2] for c in world.handler.calls] == [{"n": 0}, {"n": 1}]


def _burn(world: RunWorld, count: int) -> None:
    for i in range(count):
        world.post(world.open_session(route=f"{i:032x}", cs=bytes(32)).body)
    world.tick()


def test_SR12_prekey_burn_above_threshold_raises_one_uncapped_alert(
    running_sim: RunningSim,
) -> None:
    # Given a burn threshold of 2 per interval
    world = make_run_world(
        running_sim,
        limits=BoundaryLimits(pull_wait_s=0.001, prekey_burn_alert_threshold=2),
    )
    world.clock.now += 1
    # When three pre-keys are consumed within one interval, and the interval ends
    _burn(world, 3)
    world.clock.now += 61
    world.tick(3)
    # Then exactly one PREKEY_BURN_HIGH alert carries the interval and no count
    alerts = [
        r for _k, r in world.sink.records(AuditClass.ALERT) if r.outcome == "PREKEY_BURN_HIGH"
    ]
    assert len(alerts) == 1
    assert alerts[0].count is None
    assert alerts[0].interval_start is not None and alerts[0].interval_end is not None
    assert alerts[0].interval_start < alerts[0].interval_end


def test_SR12_prekey_consumption_at_the_threshold_raises_no_alert(running_sim: RunningSim) -> None:
    # Given a burn threshold of 2 per interval
    world = make_run_world(
        running_sim,
        limits=BoundaryLimits(pull_wait_s=0.001, prekey_burn_alert_threshold=2),
    )
    world.clock.now += 1
    # When exactly two pre-keys are consumed and the interval ends
    _burn(world, 2)
    world.clock.now += 61
    world.tick(3)
    # Then no alert is written ("above" the threshold only)
    assert [r for _k, r in world.sink.records(AuditClass.ALERT)] == []


def test_FR04_acked_garbage_is_not_redelivered_or_reprocessed(running_sim: RunningSim) -> None:
    # Given a garbage message pulled and processed
    world = make_run_world(running_sim)
    world.post(b"\xff\x00garbage")
    assert world.loop.tick().processed == 1
    # When the queue's ack deadline passes
    world.clock.now += 120
    # Then it is not delivered again (the workload acks permanently rejected messages)
    assert world.loop.tick().processed == 0
    world.clock.now += 61
    world.tick(2)
    counts = {r.outcome: r.count for _k, r in world.sink.records(AuditClass.AGGREGATE)}
    assert counts == {"REQUEST_INVALID": 1}


def test_FR04_bundle_is_republished_with_the_refreshed_token_and_same_identity_key(
    running_sim: RunningSim,
) -> None:
    # Given a workload whose token becomes due for refresh one second after issue
    world = make_run_world(running_sim, params=ChannelParams(refresh_margin_s=3599))
    before = world.bundle()
    # When time passes the republish minimum and a refresh succeeds
    world.clock.now += 10
    world.tick(2)
    after = world.bundle()
    # Then the published token is the new one, under the same identity key, with signed pre-keys
    assert after["token"] != before["token"]
    assert after["IK_pub"] == before["IK_pub"] and after["instance_id"] == before["instance_id"]
    assert all(
        prekey_signature_valid(after["IK_pub"], after["instance_id"], e) for e in after["prekeys"]
    )


def test_FR04_prekeys_are_topped_up_and_ids_are_never_reused(running_sim: RunningSim) -> None:
    # Given a workload from which almost all pre-keys have been consumed
    world = make_run_world(running_sim)
    first = world.bundle()
    ids_before = [e["id"] for e in first["prekeys"]]
    consumed = len(ids_before) - 10
    world.clock.now += 1
    for i in range(consumed):
        world.post(world.open_session(route=f"{i + 1:032x}", cs=bytes(32)).body)
        if i % 20 == 19:
            world.tick()
    world.tick()
    # When the republish interval passes and the loop ticks
    world.clock.now += 10
    world.tick(2)
    # Then new pre-keys appear, with ascending ids that were never used before
    after = [e["id"] for e in world.bundle()["prekeys"]]
    assert after == sorted(set(after)) and len(after) > 10
    new_ids = set(after) - set(ids_before)
    assert new_ids and min(new_ids) > max(ids_before)
