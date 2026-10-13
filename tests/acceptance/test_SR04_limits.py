"""SR-4 abuse and resource controls for the INC-2 workload channel (B-08, R-8, caps, floods).

Owning tasks: T-29 (run loop, B-08 backoff), T-23 (session table eviction), T-10 (replay cache),
T-28 (server limits), T-24 (queue), T-22 (pre-keys). Gateway budgets are in test_FR05_transport.py.
Expected failure on trunk: NotImplementedError('T-29' | 'T-23' | 'T-10' | 'T-24' | 'T-22').
"""

import os
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from acc_channel import (
    CLIENT_ID,
    CS,
    cbor,
    make_world,
    nonce,
    read_open_result,
)
from acc_runloop import make_run_world
from acc_support import FakeClock, RunningSim
from teecustody.attest import RefreshOutcome
from teecustody.channel import (
    CloseReason,
    ReplayCache,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
)
from teecustody.channel.codec import FrameAad
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.runtime import StopCode, WorkloadStopped
from teecustody.secrets import Secret

IID = "ab" * 16
RETRY_MIN, RETRY_MAX = 30, 300


# ---------------------------------------------------------------- B-08: attestation retry backoff
def _backoff_world(rs: RunningSim) -> Any:
    # A margin of 3599 s makes a 3600 s token due for refresh one second after issue, with ample
    # lifetime left for the whole doubling sequence below.
    return make_run_world(
        rs,
        params=ChannelParams(refresh_margin_s=3599),
        limits=BoundaryLimits(
            pull_wait_s=0.001, attestation_retry_min_s=RETRY_MIN, attestation_retry_max_s=RETRY_MAX
        ),
    )


def test_SR04_a_thousand_ticks_with_a_failing_launcher_make_exactly_one_call(
    running_sim: RunningSim,
) -> None:
    # Given a started workload whose token is due for refresh and a launcher that now fails
    world = _backoff_world(running_sim)
    assert world.launcher.calls == 1  # start()
    world.clock.now += 2
    world.launcher.fail = True
    # When 1,000 ticks run within attestation_retry_min_s
    for _ in range(1000):
        world.loop.tick()
    # Then the launcher was called exactly once more
    assert world.launcher.calls == 2


def test_SR04_backoff_doubles_up_to_the_maximum_and_success_resets_it(
    running_sim: RunningSim,
) -> None:
    # Given a failing launcher and a due refresh
    world = _backoff_world(running_sim)
    world.clock.now += 2
    world.launcher.fail = True
    world.loop.tick()
    calls = world.launcher.calls
    # When time advances by each expected delay (30, 60, 120, 240, then capped at 300, 300)
    for delay in (30, 60, 120, 240, 300, 300):
        world.clock.now += delay - 1
        world.tick(50)
        # Then no attempt is made one second early
        assert world.launcher.calls == calls, delay
        world.clock.now += 1
        world.tick(50)
        # And exactly one attempt is made at the delay
        calls += 1
        assert world.launcher.calls == calls, delay
    # When the launcher recovers
    world.launcher.fail = False
    world.clock.now += RETRY_MAX
    report = world.loop.tick()
    # Then the refresh succeeds
    assert report.refresh is RefreshOutcome.REFRESHED
    # And the next failure starts again from the minimum delay
    world.clock.now += 2
    world.launcher.fail = True
    world.loop.tick()
    calls = world.launcher.calls
    world.clock.now += RETRY_MIN - 1
    world.tick(20)
    assert world.launcher.calls == calls
    world.clock.now += 1
    world.tick(20)
    assert world.launcher.calls == calls + 1


def test_SR04_expired_token_stops_the_workload_and_withdraws_the_bundle(
    running_sim: RunningSim,
) -> None:
    # Given a workload whose launcher fails until the token has expired
    world = _backoff_world(running_sim)
    world.launcher.fail = True
    world.clock.now += 3600 + 31  # beyond exp and beyond the first backoff
    # When it ticks
    with pytest.raises(WorkloadStopped) as stopped:
        world.tick(5)
    # Then it stops fail-closed and no bundle remains published
    assert stopped.value.code is StopCode.ATTESTATION_EXPIRED
    assert world.queue.list_bundles(16) == []


# ---------------------------------------------------------------- R-8: session table
def _table(clock: FakeClock, closes: list[Any], max_sessions: int = 2) -> SessionTable:
    return SessionTable(
        instance_id=IID,
        max_sessions=max_sessions,
        idle_timeout_s=900,
        evict_min_idle_s=60,
        on_close=lambda info, reason: closes.append((info.session_id, reason)),
        clock=clock,
    )


def _create(table: SessionTable, sid: bytes, client: str) -> tuple[Any, bytes]:
    key = os.urandom(32)
    session = table.create(
        session_id=sid,
        client_id=client,
        sk_c2t=Secret(key),
        t2c=T2cSealer(Secret(os.urandom(32))),
    )
    return session, key


def _frame(key: bytes, sid: bytes, seq: int, good: bool = True) -> tuple[FrameAad, bytes, bytes]:
    aad_bytes = cbor({"session_id": sid, "seq": seq, "op": "test.echo"})
    ct = AESGCM(key if good else bytes(32)).encrypt(nonce(seq), b"p", aad_bytes)
    return FrameAad(session_id=sid, seq=seq, op="test.echo"), aad_bytes, ct


def test_SR04_a_full_table_with_only_active_sessions_rejects_and_evicts_nobody() -> None:
    # Given a full table whose sessions are both younger than session_evict_min_idle_s
    clock, closes = FakeClock(), []
    table = _table(clock, closes)
    _create(table, b"\x01" * 16, "a1" * 16)
    _create(table, b"\x02" * 16, "b2" * 16)
    clock.now += 30
    # When a third principal opens
    with pytest.raises(OverflowError, match="SESSIONS_FULL"):
        _create(table, b"\x03" * 16, "c3" * 16)
    # Then nobody was evicted
    assert closes == []
    assert table.get(b"\x01" * 16) is not None and table.get(b"\x02" * 16) is not None


def test_SR04_the_least_recently_active_idle_session_is_evicted_and_only_one() -> None:
    # Given a full table; session 1 idle for 100 s, session 2 refreshed by an authenticated frame
    clock, closes = FakeClock(), []
    table = _table(clock, closes)
    _create(table, b"\x01" * 16, "a1" * 16)
    s2, k2 = _create(table, b"\x02" * 16, "b2" * 16)
    clock.now += 90
    aad, aad_bytes, ct = _frame(k2, b"\x02" * 16, 0)
    s2.open_c2t(aad, aad_bytes, ct, clock())
    clock.now += 10
    # When a third principal opens
    _create(table, b"\x03" * 16, "c3" * 16)
    # Then exactly session 1 is evicted (EVICTED), and sessions 2 and 3 live
    assert closes == [(b"\x01" * 16, CloseReason.EVICTED)]
    assert table.get(b"\x01" * 16) is None
    assert table.get(b"\x02" * 16) is not None and table.get(b"\x03" * 16) is not None


def test_SR04_idle_ties_are_broken_by_the_smallest_session_id() -> None:
    # Given two sessions created at the same instant (larger id created first), both idle >= 60 s
    clock, closes = FakeClock(), []
    table = _table(clock, closes)
    _create(table, b"\x09" * 16, "b2" * 16)
    _create(table, b"\x01" * 16, "a1" * 16)
    clock.now += 61
    # When the table is full and a new principal opens
    _create(table, b"\x05" * 16, "c3" * 16)
    # Then the smallest session id is evicted
    assert closes == [(b"\x01" * 16, CloseReason.EVICTED)]


def test_SR04_an_unauthenticated_frame_never_refreshes_activity() -> None:
    # Given a full table; session 1 receives only a forged frame while idle
    clock, closes = FakeClock(), []
    table = _table(clock, closes)
    s1, _k1 = _create(table, b"\x01" * 16, "a1" * 16)
    _create(table, b"\x02" * 16, "b2" * 16)
    clock.now += 50
    aad, aad_bytes, ct = _frame(bytes(32), b"\x01" * 16, 0, good=False)
    with pytest.raises(SessionReject) as exc:
        s1.open_c2t(aad, aad_bytes, ct, clock())
    assert exc.value.code is SessionRejectCode.AUTH_FAILED
    clock.now += 20
    # When a third principal opens (session 1 is idle 70 s since creation)
    _create(table, b"\x03" * 16, "c3" * 16)
    # Then session 1 is evicted: had the forged frame refreshed it, session 2 would have gone
    assert closes == [(b"\x01" * 16, CloseReason.EVICTED)]


def test_SR04_sessions_idle_past_the_timeout_are_closed() -> None:
    # Given an open session and an idle timeout of 900 s
    clock, closes = FakeClock(), []
    table = _table(clock, closes, max_sessions=8)
    _create(table, b"\x01" * 16, "a1" * 16)
    clock.now += 899
    assert table.expire_idle() == 0
    clock.now += 1
    # When exactly the timeout has elapsed
    # Then it is closed with IDLE_TIMEOUT
    assert table.expire_idle() == 1
    assert closes == [(b"\x01" * 16, CloseReason.IDLE_TIMEOUT)]


def test_SR04_the_channel_answers_limit_exceeded_when_the_session_table_is_full() -> None:
    # Given a workload limited to one session and two clients that both know their shares
    other = "c4" * 16
    world = make_world(
        limits=BoundaryLimits(max_sessions=1),
        shares={CLIENT_ID: CS, other: CS},
    )
    _first, opened = world.established(route=CLIENT_ID)
    # When a second client opens while the first is active
    sent = world.open_session(route=other)
    result = world.server.process(sent.body)
    # Then the second gets an authenticated LIMIT_EXCEEDED with no session, and the first survives
    assert result.response is not None
    refused = read_open_result(result.response.body, sent.t2c)
    assert not refused.ok and refused.session_id is None and refused.error == "LIMIT_EXCEEDED"
    assert opened.session_id is not None and world.sessions.get(opened.session_id) is not None
    request = world.opener.requests[-1]  # type: ignore[attr-defined]
    assert (request.session_id, CloseReason.OPEN_ABORTED) in world.closes
    assert world.flush_aggregates() == {"CHANNEL_LIMIT_EXCEEDED": 1}


# ---------------------------------------------------------------- replay cache bound
def test_SR04_a_full_replay_cache_refuses_new_entries_without_evicting_live_ones() -> None:
    # Given a cache of two entries
    clock = FakeClock()
    cache = ReplayCache(skew_s=300, max_entries=2, clock=clock)
    now = int(clock.now)
    cache.record(CLIENT_ID, b"1" * 16, now)
    cache.record(CLIENT_ID, b"2" * 16, now)
    # When a third is recorded
    with pytest.raises(OverflowError, match="REPLAY_CACHE_FULL"):
        cache.record(CLIENT_ID, b"3" * 16, now)
    # Then both live entries are still detected as replays
    assert cache.seen(CLIENT_ID, b"1" * 16) and cache.seen(CLIENT_ID, b"2" * 16)


def test_SR04_a_full_replay_cache_makes_the_channel_answer_limit_exceeded() -> None:
    # Given a workload whose replay cache holds one entry
    world = make_world(limits=BoundaryLimits(replay_cache_max_entries=1))
    assert world.established()[1].ok
    # When another client opens
    sent = world.open_session(route="c5" * 16)
    result = world.server.process(sent.body)
    # Then it is told LIMIT_EXCEEDED and counted
    assert result.response is not None
    assert read_open_result(result.response.body, sent.t2c).error == "LIMIT_EXCEEDED"
    assert world.flush_aggregates() == {"CHANNEL_LIMIT_EXCEEDED": 1}


# ---------------------------------------------------------------- flood isolation
def test_SR04_a_flood_of_rejected_opens_for_one_route_does_not_stop_that_routes_next_open() -> None:
    # Given an attacker who claims the victim's id with a wrong share, 30 times
    world = make_world()
    for _ in range(30):
        sent = world.open_session(cs=bytes(32))
        result = world.server.process(sent.body)
        assert result.response is not None
        assert read_open_result(result.response.body, sent.t2c).error == "AUTHENTICATION_FAILED"
    # When the victim then opens with the right share
    legit = world.open_session()
    result = world.server.process(legit.body)
    # Then the open succeeds, and the flood is recorded as one bounded aggregate
    assert str(result.outcome) == "SESSION_OPENED"
    assert world.flush_aggregates() == {"OPEN_REJECTED": 30}


def test_SR04_no_inbound_socket_is_bound_or_listened_on_by_the_run_loop(
    running_sim: RunningSim, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given a simulator already running and a socket layer that forbids bind/listen
    import socket

    def deny(*_a: object, **_k: object) -> None:
        raise AssertionError("INBOUND_SOCKET")

    monkeypatch.setattr(socket.socket, "bind", deny)
    monkeypatch.setattr(socket.socket, "listen", deny)
    # When the workload starts, publishes its bundle and serves ticks (including an open)
    world = make_run_world(running_sim)
    world.post(world.open_session().body)
    world.tick(3)
    # Then no inbound socket was ever created (NFR-2)
    assert world.responses(CLIENT_ID)
