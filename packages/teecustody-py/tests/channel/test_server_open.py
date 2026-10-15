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
    cbor,
    open_session_plaintext,
    read_open_result,
    reenvelope,
    seal_open,
)
from support_server import make_world as _make_world

from teecustody.channel import server as server_module
from teecustody.channel.server import ProcessResult
from teecustody.config import ChannelParams
from teecustody.secrets import Secret

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


# ---------------------------------------------------------------- criterion 3
class TakeSpy:
    def __init__(self, world: World, monkeypatch: pytest.MonkeyPatch) -> None:
        self.taken: list[Secret] = []
        real = world.prekeys.take

        def spy(prekey_id: int) -> Secret:
            secret = real(prekey_id)
            self.taken.append(secret)
            return secret

        monkeypatch.setattr(world.prekeys, "take", spy)


def _flip_last_hex(text: str) -> str:
    return text[:-1] + ("1" if text[-1] == "0" else "0")


def _flip_first_byte(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


@pytest.mark.parametrize(
    "change",
    [
        lambda aad: {"client_id": _flip_last_hex(aad["client_id"])},
        lambda aad: {"request_id": _flip_first_byte(aad["request_id"])},
        lambda aad: {"timestamp": aad["timestamp"] - 1},
    ],
    ids=["client_id", "request_id", "timestamp"],
)
def test_one_aad_change_that_still_decodes_fails_open(
    monkeypatch: pytest.MonkeyPatch, change: Callable[[dict[str, Any]], dict[str, Any]]
) -> None:
    world = _make_world()
    sent = world.open_session()
    taken = TakeSpy(world, monkeypatch)

    result = world.process(reenvelope(sent, **change(sent.aad)))

    _assert_open_failed(world, result, sent.aad["prekey_id"], taken)


def test_envelope_moved_from_another_instance_and_rewritten_fails_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _make_world()
    other = _make_world(instance_id=OTHER_INSTANCE_ID)
    sent = other.open_session()
    target = world.entry()
    taken = TakeSpy(world, monkeypatch)

    result = world.process(reenvelope(sent, instance_id=INSTANCE_ID, prekey_id=target.id))

    _assert_open_failed(world, result, target.id, taken)


def test_open_sealed_with_the_wrong_info_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _make_world()
    target = world.entry()
    sent = seal_open(
        ik_pub=world.ik_pub,
        prekey=target,
        aad=world.aad(prekey=target),
        plaintext=open_session_plaintext(),
        info_prekey_id=target.id + 1,
    )
    taken = TakeSpy(world, monkeypatch)

    result = world.process(sent.body)

    _assert_open_failed(world, result, target.id, taken)


def _assert_open_failed(
    world: World, result: ProcessResult, prekey_id: int, taken: TakeSpy
) -> None:
    assert str(result.outcome) == "OPEN_FAILED"
    assert result.response is None
    assert dict(world.audit.counts) == {"OPEN_FAILED": 1}
    assert all(entry.id != prekey_id for entry in world.prekeys.public_entries())
    assert len(taken.taken) == 1
    assert taken.taken[0].wiped
    assert world.opener.requests == []


def test_every_one_byte_aad_change_is_refused_and_reaching_hpke_means_open_failed() -> None:
    world = _make_world(params=ChannelParams(prekey_batch=256, prekey_low_water=1))
    reached_hpke = 0
    probe = world.open_session()
    for position in range(len(probe.aad_bytes)):
        target = world.entry()
        sent = world.open_session(prekey=target)
        aad_bytes = bytearray(sent.aad_bytes)
        aad_bytes[position] ^= 0x01
        body = cbor({"kind": "open", "aad": bytes(aad_bytes), "enc": sent.enc, "ct": sent.ct})
        before = len(world.prekeys.public_entries())

        result = world.process(body)

        assert result.response is None
        assert str(result.outcome) != "SESSION_OPENED"
        if str(result.outcome) == "OPEN_FAILED":
            reached_hpke += 1
            assert len(world.prekeys.public_entries()) == before - 1
    assert reached_hpke >= 32
    assert world.opener.requests == []


# ---------------------------------------------------------------- criterion 4
@pytest.mark.parametrize(
    "plaintext",
    [b"\xff", cbor({"op": "nope"}), cbor({"op": "open_session", "cs": b"short"})],
    ids=["not-cbor", "unknown-op", "schema"],
)
def test_invalid_open_payload_is_counted_and_answered_invalid_frame(plaintext: bytes) -> None:
    world = _make_world()
    target = world.entry()
    sent = seal_open(
        ik_pub=world.ik_pub, prekey=target, aad=world.aad(prekey=target), plaintext=plaintext
    )

    result = world.process(sent.body)

    assert str(result.outcome) == "OPEN_PAYLOAD_INVALID"
    assert dict(world.audit.counts) == {"OPEN_PAYLOAD_INVALID": 1}
    assert result.response is not None
    assert result.response.client_id == CLIENT_ID
    view = read_open_result(result.response.body, sent.t2c)
    assert view.session_id is None
    assert view.request_id == sent.aad["request_id"]
    assert view.body == {"ok": False, "error": "INVALID_FRAME"}
    assert world.opener.requests == []
