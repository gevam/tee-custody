"""T-28 criteria 1-8, 10, 13: the open path of `ChannelServer` (INC-2-API §4.8, §4.10; R-4, R-5)."""

import math
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from support_server import (
    CLIENT_ID,
    INSTANCE_ID,
    OTHER_INSTANCE_ID,
    World,
    read_open_result,
)
from support_server import make_world as _make_world

from teecustody.channel import server as server_module

ALLOWED_LOG_FIELDS = {"client_id", "session_id", "prekey_id", "request_id"}


# ---------------------------------------------------------------- criterion 1
def test_valid_open_session_opens_a_session_and_answers_on_the_aad_route() -> None:
    world = _make_world()
    sent = world.open_session()

    result = world.process(sent.body)

    assert str(result.outcome) == "SESSION_OPENED"
    assert result.response is not None
    assert result.response.client_id == CLIENT_ID
    view = read_open_result(result.response.body, sent.t2c)
    assert view.kind == "open_result"
    assert view.body == {"ok": True, "payload": {"hello": 1}}
    assert view.request_id == sent.aad["request_id"]
    assert view.session_id is not None
    session = world.sessions.get(view.session_id)
    assert session is not None
    assert session.client_id == CLIENT_ID
    request = world.opener.requests[0]
    assert request.claimed_client_id == CLIENT_ID
    assert request.instance_id == INSTANCE_ID
    assert request.session_id == view.session_id
    assert world.logger.calls == [
        (
            "info",
            "SESSION_OPENED",
            {
                "client_id": CLIENT_ID,
                "session_id": view.session_id.hex(),
                "prekey_id": sent.aad["prekey_id"],
                "request_id": sent.aad["request_id"].hex(),
            },
        )
    ]
    assert set(world.logger.calls[0][2]) <= ALLOWED_LOG_FIELDS
    assert not world.audit.counts


# ---------------------------------------------------------------- criterion 2
class OpenBaseSpy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls = 0
        real = server_module.open_base

        def spy(*args: Any) -> Any:
            self.calls += 1
            return real(*args)

        monkeypatch.setattr(server_module, "open_base", spy)


def _oversize(world: World) -> bytes:
    return b"\x00" * (world.limits.max_request_bytes + 1)


def _invalid(_world: World) -> bytes:
    return b"\xff"


def _wrong_instance(world: World) -> bytes:
    return world.open_session(instance_id=OTHER_INSTANCE_ID).body


def _unknown_prekey(world: World) -> bytes:
    return world.open_session(prekey_id=10_000).body


def _stale_past(world: World) -> bytes:
    skew = world.params.request_skew_s
    return world.open_session(timestamp=math.floor(world.clock()) - skew).body


def _stale_future(world: World) -> bytes:
    skew = world.params.request_skew_s
    return world.open_session(timestamp=math.ceil(world.clock()) + skew).body


@pytest.mark.parametrize(
    ("make_body", "code"),
    [
        (_oversize, "REQUEST_INVALID"),
        (_invalid, "REQUEST_INVALID"),
        (_wrong_instance, "REQUEST_WRONG_INSTANCE"),
        (_unknown_prekey, "PREKEY_UNKNOWN"),
        (_stale_past, "REQUEST_STALE"),
        (_stale_future, "REQUEST_STALE"),
    ],
)
def test_pre_hpke_failure_is_counted_unanswered_and_consumes_no_prekey(
    monkeypatch: pytest.MonkeyPatch, make_body: Callable[[World], bytes], code: str
) -> None:
    world = _make_world()
    body = make_body(world)
    live = world.prekeys.public_entries()
    spy = OpenBaseSpy(monkeypatch)

    result = world.process(body)

    assert str(result.outcome) == code
    assert result.response is None
    assert dict(world.audit.counts) == {code: 1}
    assert spy.calls == 0
    assert world.prekeys.public_entries() == live
    assert world.opener.requests == []


def test_timestamp_just_inside_the_skew_is_accepted_in_both_directions() -> None:
    world = _make_world()
    skew = world.params.request_skew_s
    now = world.clock()
    for timestamp in (math.ceil(now) - skew, math.floor(now) + skew):
        sent = world.open_session(prekey=world.entry(), timestamp=timestamp)
        assert str(world.process(sent.body).outcome) == "SESSION_OPENED"


def test_consumed_prekey_is_unknown_and_a_verbatim_replay_never_reaches_hpke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _make_world()
    sent = world.open_session()
    assert str(world.process(sent.body).outcome) == "SESSION_OPENED"
    live = world.prekeys.public_entries()
    spy = OpenBaseSpy(monkeypatch)

    fresh = world.open_session(
        prekey=world.prekeys.public_entries()[0], prekey_id=sent.aad["prekey_id"]
    )
    verbatim = world.process(sent.body)
    reused = world.process(fresh.body)

    assert str(verbatim.outcome) == "PREKEY_UNKNOWN"
    assert verbatim.response is None
    assert str(reused.outcome) == "PREKEY_UNKNOWN"
    assert reused.response is None
    assert dict(world.audit.counts) == {"PREKEY_UNKNOWN": 2}
    assert spy.calls == 0
    assert world.prekeys.public_entries() == live


def test_replayed_request_id_on_a_live_prekey_is_counted_and_consumes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _make_world()
    first = world.open_session(prekey=world.entry(0))
    assert str(world.process(first.body).outcome) == "SESSION_OPENED"
    replay = world.open_session(prekey=world.entry(0), request_id=first.aad["request_id"])
    live = world.prekeys.public_entries()
    spy = OpenBaseSpy(monkeypatch)

    result = world.process(replay.body)

    assert str(result.outcome) == "REQUEST_REPLAYED"
    assert result.response is None
    assert dict(world.audit.counts) == {"REQUEST_REPLAYED": 1}
    assert spy.calls == 0
    assert world.prekeys.public_entries() == live
