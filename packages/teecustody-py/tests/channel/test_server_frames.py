"""T-28 criteria 9 and 14: the frame path of `ChannelServer` (INC-2-API §4.9, §4.10 step 8-9)."""

import os
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from support_server import (
    CLIENT_ID,
    INSTANCE_ID,
    SentOpen,
    World,
    cbor,
    make_world,
    read_frame_result,
    seal_frame,
    uncbor,
)

from teecustody.channel.ports import (
    CloseReason,
    HandlerError,
    HandlerOk,
    RemoteErrorCode,
    SessionInfo,
)


def _opened() -> tuple[World, SentOpen, bytes]:
    world = make_world()
    sent, session_id = world.established()
    world.logger.calls.clear()
    return world, sent, session_id


def _echo(world: World, sent: SentOpen, session_id: bytes, seq: int, payload: Any = 1) -> Any:
    return world.process(seal_frame(sent.c2t, session_id, seq, "test.echo", cbor(payload)))


# ---------------------------------------------------------------- criterion 9
def test_valid_frames_reach_the_handler_once_and_are_answered_in_t2c_order() -> None:
    world, sent, session_id = _opened()

    first = _echo(world, sent, session_id, 0, {"n": 1})
    second = _echo(world, sent, session_id, 5, {"n": 2})

    info = SessionInfo(client_id=CLIENT_ID, session_id=session_id, instance_id=INSTANCE_ID)
    assert world.handler.calls == [(info, "test.echo", {"n": 1}), (info, "test.echo", {"n": 2})]
    views = []
    for result in (first, second):
        assert str(result.outcome) == "FRAME_ACCEPTED"
        assert result.response is not None
        assert result.response.client_id == CLIENT_ID
        views.append(read_frame_result(result.response.body, sent.t2c))
    assert [(v.kind, v.seq, v.op, v.session_id) for v in views] == [
        ("frame_result", 1, "test.echo", session_id),
        ("frame_result", 2, "test.echo", session_id),
    ]
    assert [v.body for v in views] == [
        {"re": 0, "ok": True, "payload": {"echo": {"n": 1}}},
        {"re": 5, "ok": True, "payload": {"echo": {"n": 2}}},
    ]
    assert not world.audit.counts
    assert world.logger.calls == []


def test_frame_for_an_unknown_session_is_counted_and_unanswered() -> None:
    world, sent, _session_id = _opened()

    result = _echo(world, sent, os.urandom(16), 0)

    assert str(result.outcome) == "SESSION_UNKNOWN"
    assert result.response is None
    assert dict(world.audit.counts) == {"SESSION_UNKNOWN": 1}
    assert world.handler.calls == []


def test_reused_and_backwards_seq_are_rejected_before_the_handler() -> None:
    world, sent, session_id = _opened()
    assert _echo(world, sent, session_id, 3).response is not None

    reused = _echo(world, sent, session_id, 3)
    backwards = _echo(world, sent, session_id, 2)

    for result in (reused, backwards):
        assert str(result.outcome) == "FRAME_SEQ_REJECTED"
        assert result.response is None
    assert dict(world.audit.counts) == {"FRAME_SEQ_REJECTED": 2}
    assert len(world.handler.calls) == 1


@pytest.mark.parametrize("key", ["wrong-key", "wrong-op"])
def test_frame_failing_aead_is_counted_auth_failed_and_unanswered(key: str) -> None:
    world, sent, session_id = _opened()
    body = (
        seal_frame(bytes(32), session_id, 0, "test.echo", cbor(1))
        if key == "wrong-key"
        else _with_aad_op(seal_frame(sent.c2t, session_id, 0, "test.echo", cbor(1)), "test.other")
    )

    result = world.process(body)

    assert str(result.outcome) == "FRAME_AUTH_FAILED"
    assert result.response is None
    assert dict(world.audit.counts) == {"FRAME_AUTH_FAILED": 1}
    assert world.handler.calls == []
    assert _echo(world, sent, session_id, 0).response is not None


def _with_aad_op(body: bytes, op: str) -> bytes:
    envelope = uncbor(body)
    aad = uncbor(envelope["aad"])
    aad["op"] = op
    envelope["aad"] = cbor(aad)
    return cbor(envelope)


def test_close_answers_ok_and_then_closes_the_session() -> None:
    world, sent, session_id = _opened()

    result = world.process(seal_frame(sent.c2t, session_id, 0, "close", cbor(None)))

    assert str(result.outcome) == "SESSION_CLOSED"
    assert result.response is not None
    assert result.response.client_id == CLIENT_ID
    view = read_frame_result(result.response.body, sent.t2c)
    assert (view.seq, view.op) == (1, "close")
    assert view.body == {"re": 0, "ok": True, "payload": None}
    assert world.handler.calls == []
    assert world.sessions.get(session_id) is None
    assert [reason for _info, reason in world.table_closes] == [CloseReason.CLIENT_CLOSE]
    assert world.logger.calls == []
    assert not world.audit.counts
    assert str(_echo(world, sent, session_id, 1).outcome) == "SESSION_UNKNOWN"


def test_handler_payload_over_the_result_bound_is_replaced_by_limit_exceeded() -> None:
    world, sent, session_id = _opened()
    world.handler.script = lambda _s, _op, _p: HandlerOk(b"x" * 32_768)

    result = _echo(world, sent, session_id, 0)

    assert str(result.outcome) == "FRAME_ACCEPTED"
    assert result.response is not None
    view = read_frame_result(result.response.body, sent.t2c)
    assert view.body == {"re": 0, "ok": False, "error": "LIMIT_EXCEEDED"}


def test_handler_payload_exactly_at_the_result_bound_is_delivered() -> None:
    world, sent, session_id = _opened()
    overhead = len(cbor({"re": 0, "ok": True, "payload": b"x" * 1000})) - 1000
    world.handler.script = lambda _s, _op, _p: HandlerOk(b"x" * (32_768 - overhead))

    result = _echo(world, sent, session_id, 0)

    assert result.response is not None
    view = read_frame_result(result.response.body, sent.t2c)
    assert len(cbor(view.body)) == 32_768
    assert view.body["ok"] is True


def test_undecodable_frame_payload_is_answered_invalid_frame_without_a_count() -> None:
    world, sent, session_id = _opened()

    result = world.process(seal_frame(sent.c2t, session_id, 0, "close", b"\xff"))

    assert str(result.outcome) == "FRAME_ACCEPTED"
    assert result.response is not None
    view = read_frame_result(result.response.body, sent.t2c)
    assert view.body == {"re": 0, "ok": False, "error": "INVALID_FRAME"}
    assert world.handler.calls == []
    assert world.sessions.get(session_id) is not None
    assert not world.audit.counts


def test_handler_error_and_handler_exception_are_answered_with_stable_codes() -> None:
    world, sent, session_id = _opened()
    world.handler.script = lambda _s, _op, _p: HandlerError(RemoteErrorCode.UNKNOWN_OPERATION)
    refused = _echo(world, sent, session_id, 0)

    def explode(_s: SessionInfo, _op: str, _p: Any) -> Any:
        raise RuntimeError("SENTINEL-HANDLER-TEXT-3c3c")

    world.handler.script = explode
    failed = _echo(world, sent, session_id, 1)

    bodies = []
    for result in (refused, failed):
        assert str(result.outcome) == "FRAME_ACCEPTED"
        assert result.response is not None
        bodies.append(read_frame_result(result.response.body, sent.t2c).body)
    assert bodies == [
        {"re": 0, "ok": False, "error": "UNKNOWN_OPERATION"},
        {"re": 1, "ok": False, "error": "BACKEND_UNAVAILABLE"},
    ]
    assert "SENTINEL-HANDLER-TEXT-3c3c" not in repr(failed) + repr(world.logger.calls)


# ---------------------------------------------------------------- criterion 14 (A1)
def test_authenticated_frame_with_empty_plaintext_is_auth_failed_and_unanswered() -> None:
    world, sent, session_id = _opened()

    result = world.process(seal_frame(sent.c2t, session_id, 0, "test.echo", b""))

    assert str(result.outcome) == "FRAME_AUTH_FAILED"
    assert result.response is None
    assert dict(world.audit.counts) == {"FRAME_AUTH_FAILED": 1}
    assert world.handler.calls == []
    assert _echo(world, sent, session_id, 0).response is not None
