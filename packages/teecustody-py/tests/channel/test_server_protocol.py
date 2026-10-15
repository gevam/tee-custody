"""T-28 criteria 10-13: R-5 single seal, forward secrecy, fuzz, A1 session-id collision."""

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from support_server import (
    CLIENT_ID,
    OTHER_CLIENT_ID,
    World,
    make_world,
    read_open_result,
    reject,
)

from teecustody.channel import server as server_module
from teecustody.channel.hpke import OpenedHpke
from teecustody.channel.ports import (
    OpenAccepted,
    OpenRejected,
    OpenRequest,
    OpenResult,
    RemoteErrorCode,
)
from teecustody.channel.session import T2cSealer


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
    assert all(cs.wiped for cs in world.opener.cs_seen)


def test_payload_exactly_at_the_open_result_bound_opens_the_session() -> None:
    world = make_world()
    overhead = len(server_module.encode_open_result_plaintext(OpenAccepted(CLIENT_ID, b"x" * 1000)))
    world.opener.script = _accept(CLIENT_ID, b"x" * (32_768 - (overhead - 1000)))
    sent = world.open_session()

    result = world.process(sent.body)

    assert str(result.outcome) == "SESSION_OPENED"


def test_garbage_opener_result_is_counted_once_as_open_rejected() -> None:
    world = make_world()
    world.opener.script = lambda _request: None  # type: ignore[assignment,return-value]

    world.process(world.open_session().body)

    assert dict(world.audit.counts) == {"OPEN_REJECTED": 1}
    assert world.opener.closed_calls == []
