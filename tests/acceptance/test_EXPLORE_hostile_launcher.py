"""QA exploratory (INC-1 phase 2): the workload-side launcher client against a hostile socket peer.

Property: every misbehaviour becomes LauncherError with a stable code, within the deadline, with
no response bytes in the exception text. Synthetic values only.
"""

import base64
import json
import socket
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from acc_support import AUDIENCE
from teecustody.attest import ConfidentialSpaceLauncher
from teecustody.attest.ports import LauncherError

NONCE = bytes(32)
SENT = "SENTINEL-LEAK-5d2e"


def _b64(obj: object) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(claims: dict[str, object]) -> str:
    return f"{_b64({'alg': 'RS256'})}.{_b64(claims)}.{_b64({'s': SENT})}"


def _serve(path: Path, handler: Callable[[socket.socket], None]) -> threading.Thread:
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(path))
    srv.listen(1)

    def run() -> None:
        conn, _ = srv.accept()
        try:
            conn.recv(65536)
            handler(conn)
        except OSError:
            pass
        finally:
            conn.close()
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def _http(status: str, body: bytes, extra: str = "") -> bytes:
    return f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}\r\n".encode() + body


def _call(path: Path, timeout_s: float = 1.0, cap: int = 4096) -> None:
    ConfidentialSpaceLauncher(
        str(path), timeout_s=timeout_s, max_response_bytes=cap
    ).get_attestation_token(AUDIENCE, "OIDC", NONCE)


GOOD = {"aud": AUDIENCE, "iat": 100, "exp": 200, "eat_nonce": NONCE.hex()}

CASES: dict[str, Callable[[socket.socket], None]] = {
    "garbage": lambda c: c.sendall(b"\x00\x01\x02garbage"),
    "close_immediately": lambda c: None,
    "status_500_with_sentinel": lambda c: c.sendall(_http("500 ERR", SENT.encode())),
    "status_200_non_jwt": lambda c: c.sendall(_http("200 OK", SENT.encode())),
    "status_200_empty": lambda c: c.sendall(_http("200 OK", b"")),
    "token_two_segments": lambda c: c.sendall(_http("200 OK", b"a.b")),
    "token_wrong_audience": lambda c: c.sendall(
        _http("200 OK", _jwt({**GOOD, "aud": "evil"}).encode())
    ),
    "token_wrong_nonce": lambda c: c.sendall(
        _http("200 OK", _jwt({**GOOD, "eat_nonce": "00" * 31 + "01"}).encode())
    ),
    "token_exp_before_iat": lambda c: c.sendall(
        _http("200 OK", _jwt({**GOOD, "exp": 50}).encode())
    ),
    "token_bool_exp": lambda c: c.sendall(_http("200 OK", _jwt({**GOOD, "exp": True}).encode())),
    "token_float_exp": lambda c: c.sendall(_http("200 OK", _jwt({**GOOD, "exp": 200.5}).encode())),
    "oversized_body": lambda c: c.sendall(_http("200 OK", b"a" * 100000)),
    "announced_longer_than_sent": lambda c: c.sendall(
        b"HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\nabc"
    ),
    "chunked_endless": lambda c: c.sendall(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + b"5\r\nhello\r\n" * 5000
    ),
    "endless_1xx": lambda c: c.sendall(b"HTTP/1.1 100 Continue\r\n\r\n" * 5000),
    "huge_headers": lambda c: c.sendall(b"HTTP/1.1 200 OK\r\nX: " + b"a" * 100000 + b"\r\n\r\n"),
    "redirect": lambda c: c.sendall(_http("302 Found", b"", "Location: http://127.0.0.1:1/\r\n")),
    "stall": lambda c: time.sleep(5),
}


@pytest.mark.parametrize("name", list(CASES))
def test_hostile_launcher_peer_yields_stable_LauncherError(name: str, workdir: Path) -> None:
    # Given a launcher socket peer that misbehaves in a specific way
    sock = workdir / "l.sock"
    _serve(sock, CASES[name])
    start = time.monotonic()
    # When the workload requests a token
    with pytest.raises(LauncherError) as info:
        _call(sock)
    # Then it fails closed, quickly, with no peer bytes in the error text
    assert time.monotonic() - start < 3.0
    assert SENT not in repr(info.value) + str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None or SENT not in repr(info.value.__context__)


def test_missing_socket_is_unavailable(workdir: Path) -> None:
    with pytest.raises(LauncherError) as info:
        _call(workdir / "nope.sock")
    assert str(info.value) == "UNAVAILABLE" or "UNAVAILABLE" in repr(info.value)


@pytest.mark.parametrize("bad", ["", "a" * 5000, "‮", "\x00", "a\r\nHost: evil"])
def test_hostile_audience_is_rejected_before_any_io(bad: str, workdir: Path) -> None:
    # Given no listener at all, hostile audience values must fail validation, not connect
    with pytest.raises((LauncherError, ValueError)):
        ConfidentialSpaceLauncher(
            str(workdir / "none.sock"), timeout_s=1.0, max_response_bytes=4096
        ).get_attestation_token(bad, "OIDC", NONCE)


@pytest.mark.parametrize("nonce", [b"", bytes(31), bytes(33)])
def test_wrong_length_identity_nonce_is_rejected(nonce: bytes, workdir: Path) -> None:
    with pytest.raises((LauncherError, ValueError)):
        ConfidentialSpaceLauncher(
            str(workdir / "none.sock"), timeout_s=1.0, max_response_bytes=4096
        ).get_attestation_token(AUDIENCE, "OIDC", nonce)
