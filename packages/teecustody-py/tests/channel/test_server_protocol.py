"""T-28 criteria 10-13: R-5 single seal, forward secrecy, fuzz, A1 session-id collision."""

import random
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from support_server import (
    CLIENT_ID,
    INSTANCE_ID,
    OTHER_CLIENT_ID,
    World,
    cbor,
    make_world,
    read_open_result,
    reject,
    seal_frame,
)

from teecustody.channel import server as server_module
from teecustody.channel.hpke import OpenedHpke
from teecustody.channel.ports import (
    CloseReason,
    OpenAccepted,
    OpenRejected,
    OpenRequest,
    OpenResult,
    RemoteErrorCode,
    SessionInfo,
)
from teecustody.channel.session import T2cSealer
from teecustody.config import BoundaryLimits, ChannelParams


class SealSpy:
    """Counts T2cSealer.seal_open_result calls (Session.seal_open_result delegates to it)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls = 0
        real = T2cSealer.seal_open_result

        def spy(sealer: T2cSealer, *args: Any) -> Any:
            self.calls += 1
            return real(sealer, *args)

        monkeypatch.setattr(T2cSealer, "seal_open_result", spy)


class OpenedSpy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.opened: list[OpenedHpke] = []
        real = server_module.open_base

        def spy(*args: Any) -> OpenedHpke:
            opened = real(*args)
            self.opened.append(opened)
            return opened

        monkeypatch.setattr(server_module, "open_base", spy)


class DecodedSpy:
    """Keeps every payload `decode_open_payload` returned, so its `cs` can be checked."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.payloads: list[Any] = []
        real = server_module.decode_open_payload

        def spy(*args: Any) -> Any:
            payload = real(*args)
            self.payloads.append(payload)
            return payload

        monkeypatch.setattr(server_module, "decode_open_payload", spy)


def _raise(_request: OpenRequest) -> OpenResult:
    raise RuntimeError("opener down")


def _accept(principal: Any, payload: Any = None) -> Callable[[OpenRequest], OpenResult]:
    return lambda _request: OpenAccepted(client_id=principal, payload=payload)


def _create_raises(world: World) -> None:
    def create(**_kwargs: Any) -> Any:
        raise RuntimeError("table down")

    world.sessions.create = create  # type: ignore[method-assign]


def _rng_raises(world: World) -> None:
    def rng(_n: int) -> bytes:
        raise RuntimeError("no entropy")

    world.server._rng = rng


def _closed_raises(world: World) -> None:
    world.opener.script = _accept(OTHER_CLIENT_ID)
    world.opener.closed_error = RuntimeError("closed down")


def _opener(script: Callable[[OpenRequest], Any]) -> Callable[[World], None]:
    return lambda world: setattr(world.opener, "script", script)


PATHS: list[tuple[str, Callable[[World], None], bool, str, str | None]] = [
    # (id, arrange, open_session (else enroll), outcome, error or None for ok)
    ("accepted", lambda w: None, True, "SESSION_OPENED", None),
    ("enrolled", lambda w: None, False, "SESSION_OPENED", None),
    ("opener-rejects", _opener(reject(RemoteErrorCode.NOT_AUTHORIZED)), True, "OPEN_REJECTED",
     "NOT_AUTHORIZED"),
    ("opener-raises", _opener(_raise), True, "OPEN_REJECTED", "BACKEND_UNAVAILABLE"),
    ("principal-mismatch", _opener(_accept(OTHER_CLIENT_ID)), True, "OPEN_REJECTED", "INTERNAL"),
    ("closed-raises", _closed_raises, True, "OPEN_REJECTED", "INTERNAL"),
    ("create-raises", _create_raises, True, "OPEN_REJECTED", "INTERNAL"),
    ("rng-raises", _rng_raises, True, "OPEN_REJECTED", "INTERNAL"),
    ("payload-unencodable", _opener(_accept(CLIENT_ID, 1.5)), True, "OPEN_REJECTED", "INTERNAL"),
    ("payload-oversize", _opener(_accept(CLIENT_ID, b"x" * 32_768)), True, "OPEN_REJECTED",
     "LIMIT_EXCEEDED"),
    ("rejection-code-invalid", _opener(lambda r: OpenRejected("bad")), True, "OPEN_REJECTED",
     "INTERNAL"),
    ("opener-returns-garbage", _opener(lambda r: None), True, "OPEN_REJECTED", "INTERNAL"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("arrange", "is_open_session", "outcome", "error"),
    [path[1:] for path in PATHS],
    ids=[path[0] for path in PATHS],
)
def test_every_path_after_open_seals_exactly_one_open_result_and_wipes_its_secrets(
    monkeypatch: pytest.MonkeyPatch,
    arrange: Callable[[World], None],
    is_open_session: bool,
    outcome: str,
    error: str | None,
) -> None:
    world = make_world()
    arrange(world)
    sent = world.open_session() if is_open_session else world.enroll()
    seals = SealSpy(monkeypatch)
    opened = OpenedSpy(monkeypatch)
    decoded = DecodedSpy(monkeypatch)

    result = world.process(sent.body)

    assert seals.calls == 1
    assert str(result.outcome) == outcome
    assert result.response is not None
    assert result.response.client_id == CLIENT_ID
    view = read_open_result(result.response.body, sent.t2c)
    hpke = opened.opened[0]
    assert hpke.plaintext.wiped
    if error is None:
        assert view.body["ok"] is True
        assert view.session_id is not None
        assert world.sessions.get(view.session_id) is not None
        assert not hpke.sk_c2t.wiped
        assert not hpke.sk_t2c.wiped
    else:
        assert view.body == {"ok": False, "error": error}
        assert view.session_id is None
        assert hpke.sk_c2t.wiped
        assert hpke.sk_t2c.wiped
        assert world.logger.calls == []
    assert len(decoded.payloads) == 1
    if is_open_session:
        assert decoded.payloads[0].cs.wiped
    assert all(cs.wiped for cs in world.opener.cs_seen)


def _open_payload_of_plaintext_size(size: int) -> bytes:
    overhead = len(server_module.encode_open_result_plaintext(OpenAccepted(CLIENT_ID, b"x" * 1000)))
    payload = b"x" * (size - (overhead - 1000))
    plaintext = server_module.encode_open_result_plaintext(OpenAccepted(CLIENT_ID, payload))
    assert len(plaintext) == size
    return payload


def test_payload_exactly_at_the_open_result_bound_opens_the_session() -> None:
    world = make_world()
    world.opener.script = _accept(CLIENT_ID, _open_payload_of_plaintext_size(32_768))
    sent = world.open_session()

    result = world.process(sent.body)

    assert str(result.outcome) == "SESSION_OPENED"


@pytest.mark.parametrize(
    ("payload", "error"),
    [(1.5, "INTERNAL"), (_open_payload_of_plaintext_size(32_769), "LIMIT_EXCEEDED")],
    ids=["unencodable", "one-byte-over-the-bound"],
)
def test_accepted_open_whose_result_cannot_be_sent_aborts_the_open(
    payload: Any, error: str
) -> None:
    world = make_world()
    world.opener.script = _accept(CLIENT_ID, payload)
    sent = world.open_session()

    result = world.process(sent.body)

    assert str(result.outcome) == "OPEN_REJECTED"
    assert result.response is not None
    view = read_open_result(result.response.body, sent.t2c)
    assert view.body == {"ok": False, "error": error}
    request = world.opener.requests[0]
    assert world.opener.closed_calls == [
        (
            SessionInfo(
                client_id=CLIENT_ID, session_id=request.session_id, instance_id=INSTANCE_ID
            ),
            CloseReason.OPEN_ABORTED,
        )
    ]
    assert world.sessions.get(request.session_id) is None


def test_failing_closed_hook_on_a_full_table_still_answers_limit_exceeded() -> None:
    world = make_world(limits=BoundaryLimits(max_sessions=1))
    _first, live_session_id = world.established()
    world.opener.closed_error = RuntimeError("closed down")
    sent = world.open_session(client_id=OTHER_CLIENT_ID)

    result = world.process(sent.body)

    assert str(result.outcome) == "CHANNEL_LIMIT_EXCEEDED"
    assert dict(world.audit.counts) == {"CHANNEL_LIMIT_EXCEEDED": 1}
    assert result.response is not None
    view = read_open_result(result.response.body, sent.t2c)
    assert view.body == {"ok": False, "error": "LIMIT_EXCEEDED"}
    assert [reason for _info, reason in world.opener.closed_calls] == [CloseReason.OPEN_ABORTED]
    assert world.sessions.get(live_session_id) is not None


def test_garbage_opener_result_is_counted_once_as_open_rejected() -> None:
    world = make_world()
    world.opener.script = lambda _request: None  # type: ignore[assignment,return-value]

    world.process(world.open_session().body)

    assert dict(world.audit.counts) == {"OPEN_REJECTED": 1}
    assert world.opener.closed_calls == []


# ---------------------------------------------------------------- criterion 11 (§13.3)
def test_captured_transcript_replayed_after_close_into_a_fresh_server_opens_nothing() -> None:
    world = make_world()
    sent, session_id = world.established()
    frame = seal_frame(sent.c2t, session_id, 0, "test.echo", cbor("secret"))
    close = seal_frame(sent.c2t, session_id, 1, "close", cbor(None))
    assert world.process(frame).response is not None
    assert str(world.process(close).outcome) == "SESSION_CLOSED"
    fresh = make_world(identity=world.identity, clock=world.clock)
    assert fresh.ik_pub == world.ik_pub

    outcomes = [
        [str(server.process(body).outcome) for body in (sent.body, frame, close)]
        for server in (world.server, fresh.server)
    ]

    assert outcomes[0] == ["PREKEY_UNKNOWN", "SESSION_UNKNOWN", "SESSION_UNKNOWN"]
    assert outcomes[1][0] in {"PREKEY_UNKNOWN", "OPEN_FAILED"}
    assert outcomes[1][1:] == ["SESSION_UNKNOWN", "SESSION_UNKNOWN"]
    for w in (world, fresh):
        assert w.sessions.get(session_id) is None
        assert w.opener.requests[1:] == []
    assert all(e.id != sent.aad["prekey_id"] for e in world.prekeys.public_entries())
    assert fresh.handler.calls == []


# ---------------------------------------------------------------- criterion 12 (SR-3)
def _mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        choice = rng.randrange(4)
        position = rng.randrange(len(buf)) if buf else 0
        if choice == 0 and buf:
            buf[position] ^= 1 << rng.randrange(8)
        elif choice == 1 and buf:
            buf[position] = rng.randrange(256)
        elif choice == 2:
            buf.insert(position, rng.randrange(256))
        else:
            del buf[position:]
    return bytes(buf)


def test_seeded_fuzz_of_mutated_envelopes_never_raises_and_stays_fast() -> None:
    world = make_world(params=ChannelParams(prekey_batch=256, prekey_low_water=1))
    sent, session_id = world.established()
    seeds = [
        world.open_session().body,
        world.enroll().body,
        seal_frame(sent.c2t, session_id, 7, "test.echo", cbor({"k": [1, 2, 3]})),
        seal_frame(sent.c2t, session_id, 8, "close", cbor(None)),
    ]
    rng = random.Random(0x7E28)  # noqa: S311 - a seeded, reproducible fuzz corpus
    slowest = 0.0
    outcomes = set()

    for _ in range(2_000):
        body = _mutate(rng, rng.choice(seeds))
        started = time.perf_counter()
        result = world.process(body)
        slowest = max(slowest, time.perf_counter() - started)
        outcomes.add(str(result.outcome))

    assert slowest < 0.05
    assert {"REQUEST_INVALID", "OPEN_FAILED"} <= outcomes


# ---------------------------------------------------------------- criterion 13 (A1)
def test_session_id_collision_aborts_the_open_and_leaves_the_existing_session_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = make_world()
    _first, existing_id = world.established()
    world.rng.forced.append(existing_id)
    sent = world.open_session(client_id=OTHER_CLIENT_ID)
    seals = SealSpy(monkeypatch)

    result = world.process(sent.body)

    assert seals.calls == 1
    assert str(result.outcome) == "OPEN_REJECTED"
    assert dict(world.audit.counts) == {"OPEN_REJECTED": 1}
    assert result.response is not None
    assert result.response.client_id == OTHER_CLIENT_ID
    view = read_open_result(result.response.body, sent.t2c)
    assert view.session_id is None
    assert view.body == {"ok": False, "error": "INTERNAL"}
    assert world.opener.closed_calls == [
        (
            SessionInfo(client_id=OTHER_CLIENT_ID, session_id=existing_id, instance_id=INSTANCE_ID),
            CloseReason.OPEN_ABORTED,
        )
    ]
    assert world.table_closes == []
    existing = world.sessions.get(existing_id)
    assert existing is not None
    assert existing.client_id == CLIENT_ID
