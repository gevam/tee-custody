"""T-06 criteria 3, 4 and 7: the launcher socket client (FACTS F-01..F-03, SR-3, SR-11, NFR-2)."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import math
import shutil
import socket
import socketserver
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

import teecustody.attest.launcher as launcher_module
from teecustody.attest import (
    AttestationLifecycle,
    AttestationToken,
    ConfidentialSpaceLauncher,
    LauncherError,
    LauncherErrorCode,
    RefreshOutcome,
    identity_nonce,
    launcher_nonce,
)

AUD = "https://workload.teecustody.test/aud"
IK_PUB = bytes(range(32))
NONCE = identity_nonce(IK_PUB)
HEX_NONCE = hashlib.sha256(IK_PUB).hexdigest()
MAX = 4096


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_token(*, aud: str = AUD, nonce: str = HEX_NONCE) -> str:
    claims = {"aud": aud, "iat": 1_900_000_000, "exp": 1_900_003_600, "eat_nonce": nonce}
    return f"{_b64(b'{}')}.{_b64(json.dumps(claims).encode())}.c2ln"


def http_response(status: int, body: bytes, *, content_length: int | None = None) -> bytes:
    length = len(body) if content_length is None else content_length
    head = f"HTTP/1.1 {status} X\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    return head.encode("ascii") + body


@dataclass(frozen=True)
class Reply:
    """What the fake launcher writes after reading a request.

    `hang` keeps the socket open afterwards; `drip_s` writes one byte per interval; `repeat`
    writes `data` again and again until the client goes away or the test ends.
    """

    data: bytes
    hang: bool = False
    drip_s: float = 0.0
    repeat: bool = False


@dataclass
class Received:
    request_line: str
    headers: dict[str, str]
    body: bytes


@dataclass
class FakeLauncher:
    """A scripted launcher on a Unix socket; each connection gets the next reply."""

    socket_path: Path
    replies: list[Reply] = field(default_factory=list)
    received: list[Received] = field(default_factory=list)
    connections: int = 0
    release: threading.Event = field(default_factory=threading.Event)


class _Handler(socketserver.StreamRequestHandler):
    server: _Server

    def handle(self) -> None:
        fake = self.server.fake
        fake.connections += 1
        reply = (
            fake.replies.pop(0)
            if fake.replies
            else Reply(http_response(200, make_token().encode()))
        )
        request_line = self.rfile.readline().decode("ascii").rstrip("\r\n")
        headers: dict[str, str] = {}
        while (line := self.rfile.readline().decode("ascii").rstrip("\r\n")) != "":
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        fake.received.append(Received(request_line, headers, body))
        with contextlib.suppress(OSError):
            self._write(fake, reply)
        if reply.hang:
            fake.release.wait(10)

    def _write(self, fake: FakeLauncher, reply: Reply) -> None:
        if reply.drip_s:
            chunks = [reply.data[i : i + 1] for i in range(len(reply.data))]
        else:
            chunks = [reply.data]
        while True:
            for chunk in chunks:
                self.wfile.write(chunk)
                self.wfile.flush()
                if reply.drip_s and fake.release.wait(reply.drip_s):
                    return
            if not reply.repeat or fake.release.is_set():
                return


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    block_on_close = False
    fake: FakeLauncher


@pytest.fixture
def short_dir() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="t06-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def fake_launcher(short_dir: Path) -> Iterator[FakeLauncher]:
    fake = FakeLauncher(short_dir / "teeserver.sock")
    server = _Server(str(fake.socket_path), _Handler)
    server.fake = fake
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield fake
    finally:
        fake.release.set()
        server.shutdown()
        server.server_close()
        thread.join()


def client(
    socket_path: Path, *, timeout_s: float = 2.0, max_bytes: int = MAX
) -> ConfidentialSpaceLauncher:
    return ConfidentialSpaceLauncher(
        str(socket_path), timeout_s=timeout_s, max_response_bytes=max_bytes
    )


# Criterion 3 -------------------------------------------------------------------------------


def test_token_request_matches_the_launcher_endpoint(fake_launcher: FakeLauncher) -> None:
    token = client(fake_launcher.socket_path).get_attestation_token(AUD, "OIDC", NONCE)

    assert token == AttestationToken(make_token(), 1_900_000_000, 1_900_003_600)
    [request] = fake_launcher.received
    assert request.request_line == "POST /v1/token HTTP/1.1"
    assert request.headers["host"] == "localhost"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.body) == {
        "audience": AUD,
        "nonces": [launcher_nonce(NONCE)],
        "token_type": "OIDC",
    }
    assert launcher_nonce(NONCE) == HEX_NONCE


# Criterion 4 -------------------------------------------------------------------------------


def _assert_code(
    launcher: ConfidentialSpaceLauncher,
    code: LauncherErrorCode,
    *,
    audience: str = AUD,
    token_type: str = "OIDC",  # noqa: S107 - a token type, not a secret
    nonce: bytes = NONCE,
) -> None:
    with pytest.raises(LauncherError) as caught:
        launcher.get_attestation_token(audience, token_type, nonce)
    assert caught.value.code is code
    assert str(caught.value) == code.value
    assert caught.value.args == (code.value,)


@pytest.mark.parametrize(
    ("audience", "token_type", "nonce"),
    [
        (AUD, "PKI", NONCE),
        (AUD, "oidc", NONCE),
        (AUD, "", NONCE),
        (AUD, "OIDC", NONCE[:31]),
        (AUD, "OIDC", NONCE + b"\x00"),
        (AUD, "OIDC", b""),
        ("", "OIDC", NONCE),
        ("a" * 2049, "OIDC", NONCE),
    ],
)
def test_invalid_request_is_refused_before_any_connection(
    fake_launcher: FakeLauncher, audience: str, token_type: str, nonce: bytes
) -> None:
    _assert_code(
        client(fake_launcher.socket_path),
        LauncherErrorCode.INVALID_CONFIGURATION,
        audience=audience,
        token_type=token_type,
        nonce=nonce,
    )
    assert fake_launcher.connections == 0


def test_audience_of_the_maximum_length_is_requested(fake_launcher: FakeLauncher) -> None:
    audience = "a" * 2048
    fake_launcher.replies.append(Reply(http_response(200, make_token(aud=audience).encode())))

    token = client(fake_launcher.socket_path).get_attestation_token(audience, "OIDC", NONCE)

    assert token.value == make_token(aud=audience)
    assert json.loads(fake_launcher.received[0].body)["audience"] == audience


def test_missing_socket_is_unavailable(short_dir: Path) -> None:
    _assert_code(client(short_dir / "absent.sock"), LauncherErrorCode.UNAVAILABLE)


def test_socket_nobody_listens_on_is_unavailable(short_dir: Path) -> None:
    path = short_dir / "stale.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stale:
        stale.bind(str(path))
    _assert_code(client(path), LauncherErrorCode.UNAVAILABLE)


def test_other_socket_errors_are_unavailable(short_dir: Path) -> None:
    too_long_for_af_unix = short_dir / ("x" * 200)
    _assert_code(client(too_long_for_af_unix), LauncherErrorCode.UNAVAILABLE)


def test_launcher_that_does_not_answer_in_time_is_unavailable(fake_launcher: FakeLauncher) -> None:
    fake_launcher.replies.append(Reply(b"", hang=True))
    _assert_code(client(fake_launcher.socket_path, timeout_s=0.2), LauncherErrorCode.UNAVAILABLE)


def test_launcher_that_closes_without_answering_is_unavailable(
    fake_launcher: FakeLauncher,
) -> None:
    fake_launcher.replies.append(Reply(b""))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.UNAVAILABLE)


@pytest.mark.parametrize("status", [500, 502, 503, 599])
def test_launcher_server_error_is_unavailable(fake_launcher: FakeLauncher, status: int) -> None:
    fake_launcher.replies.append(Reply(http_response(status, make_token().encode())))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.UNAVAILABLE)


@pytest.mark.parametrize("status", [201, 204, 301, 400, 401, 403, 404, 429, 499])
def test_launcher_client_error_or_other_status_is_rejected(
    fake_launcher: FakeLauncher, status: int
) -> None:
    fake_launcher.replies.append(Reply(http_response(status, make_token().encode())))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.TOKEN_REJECTED)


def test_body_of_exactly_the_maximum_size_is_accepted(fake_launcher: FakeLauncher) -> None:
    body = make_token().encode()
    fake_launcher.replies.append(Reply(http_response(200, body)))

    token = client(fake_launcher.socket_path, max_bytes=len(body)).get_attestation_token(
        AUD, "OIDC", NONCE
    )

    assert token.value == body.decode()


def test_body_over_the_maximum_size_is_rejected(fake_launcher: FakeLauncher) -> None:
    body = make_token().encode()
    fake_launcher.replies.append(Reply(http_response(200, body)))
    _assert_code(
        client(fake_launcher.socket_path, max_bytes=len(body) - 1), LauncherErrorCode.TOKEN_REJECTED
    )


def test_read_stops_after_one_byte_over_the_maximum(fake_launcher: FakeLauncher) -> None:
    # The launcher announces a huge body, sends max + 1 bytes and then stalls. A client that
    # tried to read the announced length would time out (UNAVAILABLE) instead of rejecting.
    sent = b"x" * (MAX + 1)
    fake_launcher.replies.append(
        Reply(http_response(200, sent, content_length=100 * MAX), hang=True)
    )
    _assert_code(client(fake_launcher.socket_path, timeout_s=5.0), LauncherErrorCode.TOKEN_REJECTED)


def test_body_that_is_not_utf8_is_rejected(fake_launcher: FakeLauncher) -> None:
    fake_launcher.replies.append(Reply(http_response(200, b"\xff" + make_token().encode())))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.TOKEN_REJECTED)


@pytest.mark.parametrize(
    "token",
    [
        make_token(aud="https://other.teecustody.test/aud"),
        make_token(nonce="cd" * 32),
        "not a token",
    ],
)
def test_token_for_another_audience_or_nonce_is_rejected(
    fake_launcher: FakeLauncher, token: str
) -> None:
    fake_launcher.replies.append(Reply(http_response(200, token.encode())))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.TOKEN_REJECTED)


# Criterion 7 -------------------------------------------------------------------------------


class _NullLogger:
    def info(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields

    def warning(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields

    def error(self, outcome: str, **fields: str | int) -> None:
        del outcome, fields


def test_attestation_needs_no_inbound_socket(
    fake_launcher: FakeLauncher, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(*args: object, **kwargs: object) -> None:
        raise AssertionError("INBOUND_SOCKET")

    monkeypatch.setattr(socket.socket, "bind", deny)
    monkeypatch.setattr(socket.socket, "listen", deny)
    now = [1_000.0]
    lifecycle = AttestationLifecycle(
        client(fake_launcher.socket_path),
        audience=AUD,
        token_type="OIDC",
        identity_public_key=IK_PUB,
        refresh_margin_s=300,
        clock=lambda: now[0],
        logger=_NullLogger(),
    )

    first = lifecycle.start()
    now[0] = first.expires_at - 300

    assert lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED
    assert fake_launcher.connections == 2


# Criterion 9 -------------------------------------------------------------------------------


def test_launcher_round_trip_writes_no_token_or_nonce(
    fake_launcher: FakeLauncher,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level("DEBUG")
    fake_launcher.replies.extend(
        [
            Reply(http_response(200, make_token().encode())),
            Reply(http_response(200, make_token(nonce="cd" * 32).encode())),
            Reply(http_response(503, make_token().encode())),
        ]
    )
    launcher = client(fake_launcher.socket_path)

    token = launcher.get_attestation_token(AUD, "OIDC", NONCE)
    errors = []
    for _ in range(2):
        with pytest.raises(LauncherError) as caught:
            launcher.get_attestation_token(AUD, "OIDC", NONCE)
        errors.append(caught.value)

    out, err = capsys.readouterr()
    captured = " ".join([caplog.text, out, err, repr(token), *map(str, errors), *map(repr, errors)])
    for needle in (token.value, make_token(nonce="cd" * 32), HEX_NONCE, "cd" * 32, IK_PUB.hex()):
        assert needle not in captured


# Edge cases the criteria did not name ------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"not http at all\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n" + b"X-H: 1\r\n" * 101 + b"\r\n",
        http_response(200, b"abc", content_length=50),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\nabc",
    ],
    ids=[
        "bad-status-line",
        "too-many-headers",
        "truncated-body",
        "truncated-chunk",
    ],
)
def test_malformed_http_reply_is_unavailable(fake_launcher: FakeLauncher, data: bytes) -> None:
    fake_launcher.replies.append(Reply(data))
    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.UNAVAILABLE)


# Review R1 item 3: one deadline and one byte budget for the whole exchange ---------------------

CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"


@pytest.mark.parametrize(
    ("timeout_s", "max_bytes"),
    [
        (0.0, MAX),
        (-1.0, MAX),
        (math.nan, MAX),
        (math.inf, MAX),
        (None, MAX),
        ("1", MAX),
        (1.0, 0),
        (1.0, -1),
        (1.0, True),
        (1.0, 4096.0),
        (1.0, None),
    ],
)
def test_invalid_timeout_or_size_limit_is_refused(timeout_s: object, max_bytes: object) -> None:
    with pytest.raises(LauncherError) as caught:
        ConfidentialSpaceLauncher(
            "/nonexistent.sock",
            timeout_s=timeout_s,  # type: ignore[arg-type]
            max_response_bytes=max_bytes,  # type: ignore[arg-type]
        )
    assert caught.value.code is LauncherErrorCode.INVALID_CONFIGURATION


def _timed_code(launcher: ConfidentialSpaceLauncher) -> tuple[LauncherErrorCode, float]:
    started_at = time.monotonic()
    with pytest.raises(LauncherError) as caught:
        launcher.get_attestation_token(AUD, "OIDC", NONCE)
    return caught.value.code, time.monotonic() - started_at


@pytest.mark.parametrize(
    "reply",
    [
        Reply(http_response(200, make_token().encode()), drip_s=0.1),
        Reply(CONTINUE, drip_s=0.02, repeat=True),
    ],
    ids=["slow-drip", "slow-100-continue-flood"],
)
def test_whole_exchange_is_bounded_by_one_deadline(
    fake_launcher: FakeLauncher, reply: Reply
) -> None:
    fake_launcher.replies.append(reply)

    code, elapsed = _timed_code(client(fake_launcher.socket_path, timeout_s=0.5))

    assert code is LauncherErrorCode.UNAVAILABLE
    assert elapsed < 1.5


def test_endless_100_continue_flood_exhausts_the_byte_budget(fake_launcher: FakeLauncher) -> None:
    fake_launcher.replies.append(Reply(CONTINUE * 64, repeat=True))

    code, elapsed = _timed_code(client(fake_launcher.socket_path, timeout_s=5.0))

    assert code is LauncherErrorCode.TOKEN_REJECTED
    assert elapsed < 1.5


@pytest.mark.parametrize(
    "head",
    [
        b"X-Long: " + b"a" * 70_000 + b"\r\n",
        b"".join(b"X-H%d: " % i + b"a" * 1000 + b"\r\n" for i in range(90)),
    ],
    ids=["one-long-header-line", "many-large-headers"],
)
def test_oversized_header_section_is_rejected(fake_launcher: FakeLauncher, head: bytes) -> None:
    body = make_token().encode()
    data = b"HTTP/1.1 200 OK\r\n" + head + b"Content-Length: %d\r\n\r\n" % len(body) + body
    fake_launcher.replies.append(Reply(data))

    _assert_code(client(fake_launcher.socket_path), LauncherErrorCode.TOKEN_REJECTED)


def test_deadline_already_spent_before_connecting_is_unavailable(
    fake_launcher: FakeLauncher, monkeypatch: pytest.MonkeyPatch
) -> None:
    readings = iter([100.0, 200.0, 300.0])

    class _Clock:
        @staticmethod
        def monotonic() -> float:
            return next(readings)

    monkeypatch.setattr(launcher_module, "time", _Clock)

    _assert_code(client(fake_launcher.socket_path, timeout_s=1.0), LauncherErrorCode.UNAVAILABLE)
    assert fake_launcher.connections == 0
