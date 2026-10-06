"""Contract: workload channel boundary. ChannelServer.process over real pre-keys, sessions, replay
cache and audit emitter (FR-4, SR-6, SR-12, SR-14; INC-2-API §4.7 to §4.10, §10; spec §5.4, §5.5).

Expected red until T-07, T-08, T-10, T-12, T-22, T-23, T-24 and T-28 merge
(docs/tasks/INC-2/WAVES.md).
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from tc_channel_support import (
    IMAGE_DIGEST,
    FakeClock,
    RecordingLogger,
    open_response,
    open_session_payload,
    seal_frame,
    seal_open,
)

from teecustody.audit import AggregateOutcome, AuditClass, AuditEmitter
from teecustody.channel import (
    ChannelServer,
    CloseReason,
    IdentityKey,
    OpenRequest,
    OpenResult,
    PreKeyStore,
    ReplayCache,
    SessionInfo,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
)
from teecustody.channel.codec import OpenResultAad
from teecustody.channel.ports import EnrollPayload
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.secrets import Secret
from teecustody_sim.backends import InMemoryAuditSink
from tests.support.channel_doubles import (
    EchoHandler,
    EnrollingOpener,
    MismatchingOpener,
    StaticShareOpener,
)

CLIENT = "c1" * 16
CS = bytes(range(32))


class _Workload:
    def __init__(self, opener: Any, *, max_sessions: int = 1024) -> None:
        self.clock = FakeClock()
        self.params = ChannelParams()
        self.limits = BoundaryLimits(max_sessions=max_sessions)
        self.instance_id = os.urandom(16).hex()
        self.identity = IdentityKey.generate()
        self.logger = RecordingLogger()
        self.sink = InMemoryAuditSink()
        self.audit = AuditEmitter(
            self.sink,
            interval_s=self.limits.audit_aggregate_interval_s,
            alert_cap=self.limits.audit_alert_cap,
            clock=self.clock,
            rng=os.urandom,
            logger=self.logger,
        )
        self.prekeys = PreKeyStore(
            instance_id=self.instance_id,
            identity=self.identity,
            image_digest=IMAGE_DIGEST,
            params=self.params,
            clock=self.clock,
        )
        self.prekeys.top_up()
        self.opener = opener
        self.sessions = SessionTable(
            instance_id=self.instance_id,
            max_sessions=self.limits.max_sessions,
            idle_timeout_s=self.params.idle_timeout_s,
            evict_min_idle_s=self.limits.session_evict_min_idle_s,
            on_close=lambda info, reason: opener.closed(info, reason),
            clock=self.clock,
        )
        self.handler = EchoHandler()
        self.server = ChannelServer(
            instance_id=self.instance_id,
            ik_pub=self.identity.public_bytes(),
            prekeys=self.prekeys,
            sessions=self.sessions,
            replay=ReplayCache(
                skew_s=self.params.request_skew_s,
                max_entries=self.limits.replay_cache_max_entries,
                clock=self.clock,
            ),
            opener=opener,
            handler=self.handler,
            audit=self.audit,
            params=self.params,
            limits=self.limits,
            clock=self.clock,
            rng=os.urandom,
            logger=self.logger,
        )

    def seal(self, route: str, payload: dict[str, Any], *, timestamp: int | None = None) -> Any:
        prekey = self.prekeys.public_entries()[0]
        return seal_open(
            instance_id=self.instance_id,
            ik_pub=self.identity.public_bytes(),
            prekey=prekey,
            route=route,
            payload=payload,
            timestamp=int(self.clock()) if timestamp is None else timestamp,
        )

    def aggregates(self) -> dict[str, int]:
        self.clock.now += self.limits.audit_aggregate_interval_s + 1
        self.audit.tick()
        return {
            record.outcome: record.count or 0
            for _, record in self.sink.records(AuditClass.AGGREGATE)
        }


def test_open_session_round_trip_frame_and_close() -> None:
    w = _Workload(StaticShareOpener({CLIENT: CS}))
    sealed = w.seal(CLIENT, open_session_payload(CS))

    result = w.server.process(sealed.body)

    assert result.outcome == "SESSION_OPENED"
    assert result.response is not None
    assert result.response.client_id == CLIENT
    opened = open_response(sealed.sk_t2c, result.response.body)
    assert opened.kind == "open_result"
    assert opened.aad["seq"] == 0
    assert opened.aad["request_id"] == sealed.request_id
    assert opened.plaintext["ok"] is True
    session_id = opened.aad["session_id"]
    assert isinstance(session_id, bytes)
    assert len(session_id) == 16

    echo = w.server.process(seal_frame(sealed.sk_c2t, session_id, 0, "test.echo", {"x": 1}))
    assert echo.outcome == "FRAME_ACCEPTED"
    assert echo.response is not None
    frame = open_response(sealed.sk_t2c, echo.response.body)
    assert frame.kind == "frame_result"
    assert frame.aad["seq"] == 1
    assert frame.plaintext == {"re": 0, "ok": True, "payload": {"x": 1}}

    closing = w.server.process(seal_frame(sealed.sk_c2t, session_id, 1, "close", None))
    assert closing.outcome == "SESSION_CLOSED"
    assert w.sessions.get(session_id) is None
    assert (session_id, CloseReason.CLIENT_CLOSE) in w.opener.closed_calls
    for _, outcome, fields in w.logger.lines:
        assert set(fields) <= {"client_id", "request_id", "session_id", "prekey_id", "epoch"}
        assert CS.hex() not in str(fields)
        assert outcome != ""


def test_pre_hpke_failures_are_counted_and_never_answered() -> None:
    w = _Workload(StaticShareOpener({CLIENT: CS}))
    first = w.seal(CLIENT, open_session_payload(CS))
    assert w.server.process(first.body).outcome == "SESSION_OPENED"

    replay = w.server.process(first.body)
    garbage = w.server.process(b"\xa0")
    stale = w.server.process(
        w.seal(CLIENT, open_session_payload(CS), timestamp=int(w.clock()) - 10_000).body
    )

    assert (replay.outcome, replay.response) == (AggregateOutcome.PREKEY_UNKNOWN.value, None)
    assert (garbage.outcome, garbage.response) == (AggregateOutcome.REQUEST_INVALID.value, None)
    assert (stale.outcome, stale.response) == (AggregateOutcome.REQUEST_STALE.value, None)
    counts = w.aggregates()
    assert counts["PREKEY_UNKNOWN"] == 1
    assert counts["REQUEST_INVALID"] == 1
    assert counts["REQUEST_STALE"] == 1


def test_wrong_credentials_are_rejected_with_a_nil_session() -> None:
    w = _Workload(StaticShareOpener({CLIENT: CS}))
    sealed = w.seal(CLIENT, open_session_payload(bytes(32)))

    result = w.server.process(sealed.body)

    assert result.outcome == AggregateOutcome.OPEN_REJECTED.value
    assert result.response is not None
    opened = open_response(sealed.sk_t2c, result.response.body)
    assert opened.aad["session_id"] is None
    assert opened.plaintext == {"ok": False, "error": "AUTHENTICATION_FAILED"}


class _VictimAndEnroll:
    """open_session for the victim via shares; enroll via a minting opener (R-4 test)."""

    def __init__(self) -> None:
        self.static = StaticShareOpener({CLIENT: CS})
        self.enrolling = EnrollingOpener()
        self.closed_calls: list[tuple[bytes, CloseReason]] = []

    def open(self, request: OpenRequest) -> OpenResult:
        if isinstance(request.payload, EnrollPayload):
            return self.enrolling.open(request)
        return self.static.open(request)

    def closed(self, session: SessionInfo, reason: CloseReason) -> None:
        self.closed_calls.append((session.session_id, reason))


def test_enroll_reply_route_is_never_an_identity() -> None:
    opener = _VictimAndEnroll()
    w = _Workload(opener)
    victim = w.seal(CLIENT, open_session_payload(CS))
    victim_result = w.server.process(victim.body)
    assert victim_result.response is not None
    victim_session = open_response(victim.sk_t2c, victim_result.response.body).aad["session_id"]
    assert isinstance(victim_session, bytes)

    enroll = w.seal(CLIENT, {"op": "enroll"})
    result = w.server.process(enroll.body)

    assert result.outcome == "SESSION_OPENED"
    assert opener.enrolling.requests[-1].claimed_client_id is None
    assert result.response is not None
    assert result.response.client_id == CLIENT
    assert w.sessions.get(victim_session) is not None
    assert (victim_session, CloseReason.REPLACED) not in opener.closed_calls
    minted = opener.enrolling.minted[-1]
    opened_lines = [f for _, o, f in w.logger.lines if o == "SESSION_OPENED"]
    assert opened_lines[-1]["client_id"] == minted


def test_principal_other_than_the_claim_is_refused() -> None:
    opener = MismatchingOpener("d4" * 16)
    w = _Workload(opener)
    sealed = w.seal(CLIENT, open_session_payload(CS))

    result = w.server.process(sealed.body)

    assert result.response is not None
    opened = open_response(sealed.sk_t2c, result.response.body)
    assert opened.aad["session_id"] is None
    assert opened.plaintext == {"ok": False, "error": "INTERNAL"}
    assert [reason for _, reason in opener.closed_calls] == [CloseReason.OPEN_ABORTED]


def test_frame_sequence_reuse_is_rejected_before_dispatch() -> None:
    w = _Workload(StaticShareOpener({CLIENT: CS}))
    sealed = w.seal(CLIENT, open_session_payload(CS))
    response = w.server.process(sealed.body).response
    assert response is not None
    session_id = open_response(sealed.sk_t2c, response.body).aad["session_id"]
    assert isinstance(session_id, bytes)
    frame = seal_frame(sealed.sk_c2t, session_id, 0, "test.echo", 1)
    assert w.server.process(frame).outcome == "FRAME_ACCEPTED"

    again = w.server.process(frame)

    assert (again.outcome, again.response) == (AggregateOutcome.FRAME_SEQ_REJECTED.value, None)
    assert len(w.handler.calls) == 1


def test_t2c_nonce_zero_is_one_shot() -> None:
    sealer = T2cSealer(Secret(os.urandom(32)))
    sealer.seal_open_result(OpenResultAad(session_id=None, request_id=bytes(16)), b"\xa0")
    with pytest.raises(SessionReject) as caught:
        sealer.seal_open_result(OpenResultAad(session_id=None, request_id=bytes(16)), b"\xa0")
    assert caught.value.code is SessionRejectCode.USED
