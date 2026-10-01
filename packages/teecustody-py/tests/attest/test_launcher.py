"""T-06 criteria 3, 4 and 7: the launcher socket client (FACTS F-01..F-03, SR-3, SR-11, NFR-2)."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import socketserver
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from teecustody.attest import (
    AttestationToken,
    ConfidentialSpaceLauncher,
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


def make_token(*, iat: int = 1_900_000_000, exp: int = 1_900_003_600) -> str:
    claims = {"aud": AUD, "iat": iat, "exp": exp, "eat_nonce": HEX_NONCE}
    return f"{_b64(b'{}')}.{_b64(json.dumps(claims).encode())}.c2ln"


def http_response(status: int, body: bytes) -> bytes:
    head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    return head.encode("ascii") + body


@dataclass
class Received:
    request_line: str
    headers: dict[str, str]
    body: bytes


@dataclass
class FakeLauncher:
    """A scripted launcher on a Unix socket; each connection gets the next reply."""

    socket_path: Path
    replies: list[bytes] = field(default_factory=list)
    received: list[Received] = field(default_factory=list)
    connections: int = 0
    release: threading.Event = field(default_factory=threading.Event)


class _Handler(socketserver.StreamRequestHandler):
    server: _Server

    def handle(self) -> None:
        fake = self.server.fake
        fake.connections += 1
        reply = fake.replies.pop(0) if fake.replies else http_response(200, make_token().encode())
        if reply == b"HANG":
            fake.release.wait(10)
            return
        if reply == b"CLOSE":
            return
        request_line = self.rfile.readline().decode("ascii").rstrip("\r\n")
        headers: dict[str, str] = {}
        while (line := self.rfile.readline().decode("ascii").rstrip("\r\n")) != "":
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        body = self.rfile.read(int(headers.get("content-length", "0")))
        fake.received.append(Received(request_line, headers, body))
        self.wfile.write(reply)


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
