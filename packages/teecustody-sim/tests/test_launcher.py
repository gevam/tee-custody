"""T-08 criteria 2-3: the simulated launcher token socket (spec §15.2 item 1; FACTS F-02, F-03)."""

import concurrent.futures
import contextlib
import http.client
import json
import shutil
import socket
import socketserver
import stat
import tempfile
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from teecustody_sim import LauncherServer, SimLimits
from teecustody_sim import issuer as issuer_module
from teecustody_sim import launcher as launcher_module

AUDIENCE = "https://launcher.teecustody.test/tee"
NONCE = "ab" * 32
TOKEN = "header.payload.signature"


class RecordingMint:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def __call__(self, audience: str, nonces: Sequence[str]) -> str:
        self.calls.append((audience, list(nonces)))
        return TOKEN


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path) -> None:
        super().__init__("localhost", timeout=5.0)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(str(self._socket_path))
        except OSError:
            sock.close()
            raise
        self.sock = sock


def request(
    socket_path: Path,
    body: bytes | None,
    *,
    method: str = "POST",
    path: str = "/v1/token",
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes]:
    connection = _UnixHTTPConnection(socket_path)
    try:
        connection.request(
            method, path, body=body, headers={"Content-Type": "application/json", **(headers or {})}
        )
        response = connection.getresponse()
        return response.status, response.getheader("Content-Type", ""), response.read()
    finally:
        connection.close()


def token_request(**overrides: object) -> bytes:
    fields: dict[str, object] = {"audience": AUDIENCE, "token_type": "OIDC", "nonces": [NONCE]}
    fields.update(overrides)
    return json.dumps(fields).encode()


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """AF_UNIX paths are limited to about 100 bytes, so sockets live under a short /tmp path."""
    path = Path(tempfile.mkdtemp(prefix="t08", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def mint() -> RecordingMint:
    return RecordingMint()


@pytest.fixture
def launcher(short_dir: Path, mint: RecordingMint) -> Iterator[LauncherServer]:
    server = LauncherServer(short_dir / "teeserver.sock", mint=mint, limits=SimLimits())
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_valid_request_returns_the_minted_token(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint
) -> None:
    del launcher
    status, content_type, body = request(short_dir / "teeserver.sock", token_request())

    assert status == 200
    assert content_type == "text/plain"
    assert body == TOKEN.encode()
    assert mint.calls == [(AUDIENCE, [NONCE])]


@pytest.mark.parametrize(
    "nonces",
    [
        [],
        ["a" * 10],
        ["a" * 74],
        ["\u00e9" * 5],  # 10 UTF-8 bytes
        ["\u00e9" * 37],  # 74 UTF-8 bytes
        [NONCE] * 6,
    ],
    ids=["none", "min-length", "max-length", "min-bytes-utf8", "max-bytes-utf8", "six"],
)
def test_nonces_within_the_f03_limits_are_accepted(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint, nonces: list[str]
) -> None:
    del launcher
    status, _, body = request(short_dir / "teeserver.sock", token_request(nonces=nonces))
    assert (status, body) == (200, TOKEN.encode())
    assert mint.calls == [(AUDIENCE, nonces)]


INVALID_BODIES: dict[str, bytes] = {
    "not-json": b"not json",
    "not-utf8": b'{"audience": "\xff"}',
    "array": b"[]",
    "string": b'"OIDC"',
    "missing-audience": json.dumps({"token_type": "OIDC", "nonces": []}).encode(),
    "missing-token-type": json.dumps({"audience": AUDIENCE, "nonces": []}).encode(),
    "missing-nonces": json.dumps({"audience": AUDIENCE, "token_type": "OIDC"}).encode(),
    "extra-key": token_request(extra=1),
    "duplicate-key": (
        b'{"audience": "https://a.test", "audience": "https://b.test",'
        b' "token_type": "OIDC", "nonces": []}'
    ),
    "empty-audience": token_request(audience=""),
    "audience-not-string": token_request(audience=["https://a.test"]),
    "audience-lone-surrogate": b'{"audience": "\\ud800", "token_type": "OIDC", "nonces": []}',
    "token-type-pki": token_request(token_type="PKI"),
    "token-type-empty": token_request(token_type=""),
    "token-type-lowercase": token_request(token_type="oidc"),
    "token-type-not-string": token_request(token_type=1),
    "nonces-not-list": token_request(nonces=NONCE),
    "nonce-not-string": token_request(nonces=[1234567890]),
    "nonce-too-short": token_request(nonces=["a" * 9]),
    "nonce-too-long": token_request(nonces=["a" * 75]),
    "nonce-too-long-utf8": token_request(nonces=["\u00e9" * 38]),
    "nonce-lone-surrogate": (
        b'{"audience": "a", "token_type": "OIDC", "nonces": ["\\ud800aaaaaaaaaa"]}'
    ),
    "seven-nonces": token_request(nonces=[NONCE] * 7),
    "deep-nesting": b"[" * 2000 + b"]" * 2000,
    "nan": b'{"audience": NaN, "token_type": "OIDC", "nonces": []}',
}


@pytest.mark.parametrize("body", INVALID_BODIES.values(), ids=INVALID_BODIES.keys())
def test_invalid_body_is_400_invalid_request_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint, body: bytes
) -> None:
    del launcher
    status, content_type, response = request(short_dir / "teeserver.sock", body)
    assert (status, content_type, response) == (400, "text/plain", b"INVALID_REQUEST")
    assert mint.calls == []


@pytest.mark.parametrize("path", ["/", "/v1/token/", "/v1/token?x=1", "/v1/tokens"])
def test_other_path_is_404_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint, path: str
) -> None:
    del launcher
    status, _, _ = request(short_dir / "teeserver.sock", token_request(), path=path)
    assert status == 404
    assert mint.calls == []


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def test_other_method_is_405_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint, method: str
) -> None:
    del launcher
    status, _, _ = request(short_dir / "teeserver.sock", None, method=method)
    assert status == 405
    assert mint.calls == []


def _raw_exchange(socket_path: Path, data: bytes, *, half_close: bool = False) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect(str(socket_path))
        sock.sendall(data)
        if half_close:
            sock.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def _post_head(*content_lengths: object) -> bytes:
    lines = ["POST /v1/token HTTP/1.1", "Host: localhost"]
    lines += [f"Content-Length: {value}" for value in content_lengths]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def test_missing_content_length_is_411_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint
) -> None:
    del launcher
    response = _raw_exchange(short_dir / "teeserver.sock", _post_head())
    assert response.startswith(b"HTTP/1.0 411 ")
    assert mint.calls == []


@pytest.mark.parametrize("value", ["abc", "-1", "+5", "1e3", " ", "0x10", "\u0661"])
def test_malformed_content_length_is_400_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint, value: str
) -> None:
    del launcher
    response = _raw_exchange(short_dir / "teeserver.sock", _post_head(value))
    assert response.startswith(b"HTTP/1.0 400 ")
    assert response.endswith(b"\r\n\r\nINVALID_REQUEST")
    assert mint.calls == []


def test_duplicate_content_length_is_400_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint
) -> None:
    del launcher
    body = token_request()
    response = _raw_exchange(short_dir / "teeserver.sock", _post_head(len(body), len(body)) + body)
    assert response.startswith(b"HTTP/1.0 400 ")
    assert mint.calls == []


def test_body_shorter_than_content_length_is_400_and_never_mints(
    launcher: LauncherServer, short_dir: Path, mint: RecordingMint
) -> None:
    del launcher
    body = token_request()
    response = _raw_exchange(
        short_dir / "teeserver.sock", _post_head(len(body) + 1) + body, half_close=True
    )
    assert response.startswith(b"HTTP/1.0 400 ")
    assert mint.calls == []


def test_body_over_the_limit_is_413_and_never_mints(short_dir: Path, mint: RecordingMint) -> None:
    socket_path = short_dir / "teeserver.sock"
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_request_bytes=512))
    server.start()
    try:
        audience_at_limit = "a" * (512 - len(token_request(audience="")))
        at_limit = token_request(audience=audience_at_limit)
        over_limit = token_request(audience=audience_at_limit + "a")
        rejected = _raw_exchange(socket_path, _post_head(len(over_limit)) + over_limit)
        accepted, _, _ = request(socket_path, at_limit)
    finally:
        server.stop()
    assert len(at_limit) == 512
    assert rejected.startswith(b"HTTP/1.0 413 ")
    assert accepted == 200
    assert mint.calls == [(audience_at_limit, [NONCE])]


def test_socket_is_world_connectable_like_the_real_launcher(
    launcher: LauncherServer, short_dir: Path
) -> None:
    del launcher
    socket_path = short_dir / "teeserver.sock"
    assert stat.S_ISSOCK(socket_path.stat().st_mode)
    assert stat.S_IMODE(socket_path.stat().st_mode) == 0o666


def test_stop_unlinks_the_socket_and_is_idempotent(short_dir: Path, mint: RecordingMint) -> None:
    socket_path = short_dir / "teeserver.sock"
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.stop()
    server.start()
    server.stop()
    server.stop()
    assert not socket_path.exists()
    with pytest.raises(FileNotFoundError):
        request(socket_path, token_request())


class BlockingMint:
    """Holds every call open until released, counting calls in flight."""

    def __init__(self) -> None:
        self.entered = threading.Semaphore(0)
        self.release = threading.Event()
        self.calls = 0

    def __call__(self, audience: str, nonces: Sequence[str]) -> str:
        self.calls += 1
        self.entered.release()
        assert self.release.wait(timeout=10.0)
        return TOKEN


def test_requests_beyond_max_concurrent_get_503(short_dir: Path) -> None:
    socket_path = short_dir / "teeserver.sock"
    mint = BlockingMint()
    limit = 2
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_concurrent_requests=limit))
    server.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=limit) as pool:
            held = [pool.submit(request, socket_path, token_request()) for _ in range(limit)]
            for _ in range(limit):
                assert mint.entered.acquire(timeout=10.0)

            extra_status, extra_type, extra_body = request(socket_path, token_request())

            mint.release.set()
            held_results = [future.result(timeout=10.0) for future in held]
        after_status, _, _ = request(socket_path, token_request())
    finally:
        mint.release.set()
        server.stop()

    assert (extra_status, extra_type) == (503, "text/plain")
    assert extra_body == b"SERVICE_UNAVAILABLE"
    assert [status for status, _, _ in held_results] == [200] * limit
    assert after_status == 200
    assert mint.calls == limit + 1


def test_stop_waits_for_the_request_in_flight(short_dir: Path) -> None:
    socket_path = short_dir / "teeserver.sock"
    mint = BlockingMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.start()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            in_flight = pool.submit(request_until_eof, socket_path, token_request())
            assert mint.entered.acquire(timeout=10.0)
            stopper = threading.Thread(target=server.stop)
            stopper.start()
            stopper.join(timeout=0.3)
            still_stopping = stopper.is_alive()

            mint.release.set()
            stopper.join(timeout=5.0)
            result = in_flight.result(timeout=5.0)
    finally:
        mint.release.set()
        server.stop()

    assert still_stopping
    assert not stopper.is_alive()
    assert result == (200, "text/plain", TOKEN.encode())
    assert not socket_path.exists()


class FailingMint:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, audience: str, nonces: Sequence[str]) -> str:
        self.calls += 1
        raise RuntimeError("-----BEGIN PRIVATE KEY----- leaked detail")


def request_until_eof(socket_path: Path, body: bytes) -> tuple[int, str, bytes]:
    """POST /v1/token over a raw socket, reading until the server closes the connection."""
    head = _post_head(len(body)).replace(b"\r\n\r\n", b"\r\nContent-Type: application/json\r\n\r\n")
    response_head, _, response_body = _raw_exchange(socket_path, head + body).partition(b"\r\n\r\n")
    status_line, *header_lines = response_head.decode("latin-1").split("\r\n")
    headers = dict(line.split(": ", 1) for line in header_lines)
    return int(status_line.split(" ")[1]), headers.get("Content-Type", ""), response_body


def test_mint_failure_is_500_without_detail_and_releases_its_slot(
    short_dir: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    socket_path = short_dir / "teeserver.sock"
    mint = FailingMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_concurrent_requests=1))
    server.start()
    try:
        results = [request_until_eof(socket_path, token_request()) for _ in range(3)]
    finally:
        server.stop()

    assert results == [(500, "text/plain", b"INTERNAL_ERROR")] * 3
    assert mint.calls == 3
    captured = capfd.readouterr()
    assert "PRIVATE KEY" not in captured.out + captured.err


def test_slot_is_free_once_the_client_sees_eof(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = launcher_module._LauncherUnixServer.shutdown_request

    def slow_shutdown(server: socketserver.BaseServer, sock: socket.socket) -> None:
        original(server, sock)
        time.sleep(0.1)

    monkeypatch.setattr(launcher_module._LauncherUnixServer, "shutdown_request", slow_shutdown)
    socket_path = short_dir / "teeserver.sock"
    mint = FailingMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_concurrent_requests=1))
    server.start()
    try:
        results = [request_until_eof(socket_path, token_request()) for _ in range(3)]
    finally:
        server.stop()

    assert results == [(500, "text/plain", b"INTERNAL_ERROR")] * 3
    assert mint.calls == 3


@pytest.mark.parametrize(
    "partial",
    [b"", b"POST /v1/token HTTP/1.1\r\n", _post_head(len(token_request())) + b'{"aud'],
    ids=["nothing", "partial-head", "partial-body"],
)
def test_stalled_client_is_disconnected(
    short_dir: Path, mint: RecordingMint, monkeypatch: pytest.MonkeyPatch, partial: bytes
) -> None:
    monkeypatch.setattr(issuer_module, "_REQUEST_DEADLINE_S", 0.2)
    socket_path = short_dir / "teeserver.sock"
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect(str(socket_path))
            sock.sendall(partial)
            assert sock.recv(65536) == b""
    finally:
        server.stop()
    assert mint.calls == []


def _unix_connect(socket_path: Path) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(socket_path))  # blocking: waits for backlog space instead of EAGAIN
    sock.settimeout(5.0)
    return sock


def test_slow_drip_body_is_cut_off_by_one_request_deadline(
    short_dir: Path, mint: RecordingMint, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(issuer_module, "_REQUEST_DEADLINE_S", 0.5)
    socket_path = short_dir / "teeserver.sock"
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.start()
    try:
        with _unix_connect(socket_path) as sock:
            start = time.monotonic()
            sock.settimeout(0.1)
            sock.sendall(_post_head(4000) + b'{"audience": "')
            answered = False
            while not answered and time.monotonic() - start < 4.0:
                # The server cutting the connection is an empty read, a reset or a broken pipe.
                try:
                    sock.recv(65536)
                    answered = True
                except ConnectionResetError:
                    answered = True
                except TimeoutError:
                    try:
                        sock.sendall(b"a")
                    except (BrokenPipeError, ConnectionResetError):
                        answered = True
            elapsed = time.monotonic() - start
    finally:
        server.stop()
    assert elapsed < 1.5
    assert mint.calls == []


def test_connection_flood_is_capped_and_the_launcher_recovers(
    short_dir: Path, mint: RecordingMint, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(issuer_module, "_REQUEST_DEADLINE_S", 0.5)
    socket_path = short_dir / "teeserver.sock"
    limit = 2
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_concurrent_requests=limit))
    server.start()
    baseline = threading.active_count()
    flood = [_unix_connect(socket_path) for _ in range(40)]
    try:
        time.sleep(0.3)
        assert threading.active_count() <= baseline + 2 * limit
        start = time.monotonic()
        for sock in flood:
            try:
                while sock.recv(65536):
                    pass
            except ConnectionResetError:
                pass
        assert time.monotonic() - start < 2.0
        status, _, body = request(socket_path, token_request())
    finally:
        for sock in flood:
            sock.close()
        server.stop()
    assert (status, body) == (200, TOKEN.encode())


BURST_CLIENTS = 100
BUSY_RESPONSE = (
    b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n"
    b"Connection: close\r\n\r\nSERVICE_UNAVAILABLE"
)


class EventMint:
    """Every call blocks until `release` is set."""

    def __init__(self) -> None:
        self.entered = threading.Semaphore(0)
        self.release = threading.Event()

    def __call__(self, audience: str, nonces: Sequence[str]) -> str:
        self.entered.release()
        assert self.release.wait(timeout=30.0)
        return TOKEN


def _complete_response(data: bytes) -> tuple[int, bytes] | None:
    """(status, body) for a whole HTTP/1.x response whose body matches Content-Length, else None."""
    head, separator, body = data.partition(b"\r\n\r\n")
    status_line, *header_lines = head.split(b"\r\n")
    version, _, rest = status_line.partition(b" ")
    headers = dict(line.lower().partition(b":")[::2] for line in header_lines)
    if not separator or not version.startswith(b"HTTP/1."):
        return None
    if headers.get(b"content-length", b"").strip() != str(len(body)).encode():
        return None
    return int(rest[:3]), body


def _burst_client(socket_path: Path, payload: bytes) -> tuple[str, bytes]:
    """Connect, send the request, read to EOF. A reset after the peer's data ends the read."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10.0)
        try:
            sock.connect(str(socket_path))
        except OSError as error:
            return "connect:" + type(error).__name__, b""
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            sock.sendall(payload)
        received = b""
        try:
            while chunk := sock.recv(65536):
                received += chunk
        except ConnectionResetError:
            pass
        except OSError as error:
            return "recv:" + type(error).__name__, received
    return "read", received


def test_burst_of_100_gets_8_tokens_and_92_explicit_503s(short_dir: Path) -> None:
    socket_path = short_dir / "teeserver.sock"
    mint = EventMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.start()
    payload = _post_head(len(token_request())) + token_request()
    outcomes: list[tuple[str, bytes]] = []
    busy = threading.Condition()

    def client() -> None:
        outcome = _burst_client(socket_path, payload)
        with busy:
            outcomes.append(outcome)
            busy.notify_all()

    def busy_count() -> int:
        busy_response = (503, b"SERVICE_UNAVAILABLE")
        return sum(_complete_response(data) == busy_response for _, data in outcomes)

    threads = [threading.Thread(target=client) for _ in range(BURST_CLIENTS)]
    try:
        for thread in threads:
            thread.start()
        with busy:
            reached = busy.wait_for(
                lambda: busy_count() == BURST_CLIENTS - 8 or len(outcomes) == BURST_CLIENTS,
                timeout=30.0,
            )
        mint.release.set()
        for thread in threads:
            thread.join(timeout=30.0)
    finally:
        mint.release.set()
        server.stop()

    assert reached
    assert [kind for kind, _ in outcomes if kind != "read"] == []
    responses = [_complete_response(data) for _, data in outcomes]
    assert None not in responses
    assert sorted(responses, key=repr) == sorted(
        [(200, TOKEN.encode())] * 8 + [(503, b"SERVICE_UNAVAILABLE")] * (BURST_CLIENTS - 8),
        key=repr,
    )


def _wait_for_threads(count: int) -> None:
    deadline = time.monotonic() + 10.0
    while threading.active_count() != count:
        assert time.monotonic() < deadline, threading.active_count()
        time.sleep(0.01)


def test_beyond_slot_and_overflow_the_reply_is_the_fixed_503_without_a_thread(
    short_dir: Path,
) -> None:
    socket_path = short_dir / "teeserver.sock"
    mint = EventMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits(max_concurrent_requests=1))
    server.start()
    baseline = threading.active_count()
    with _unix_connect(socket_path) as slot_holder, _unix_connect(socket_path) as overflow_holder:
        try:
            slot_holder.sendall(_post_head(len(token_request())) + token_request())
            assert mint.entered.acquire(timeout=10.0)
            overflow_holder.send(b"POST")
            _wait_for_threads(baseline + 2)

            payload = _post_head(len(token_request())) + token_request()
            kind, data = _burst_client(socket_path, payload)
            threads_after = threading.active_count()
        finally:
            mint.release.set()
            overflow_holder.close()
            server.stop()

    assert (kind, data) == ("read", BUSY_RESPONSE)
    assert threads_after == baseline + 2


def test_client_gone_before_the_reply_logs_a_fixed_code_and_nothing_on_stderr(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    records: list[tuple[str, str, str, dict[str, str | int]]] = []

    class Recorder:
        def __init__(self, name: str) -> None:
            self._name = name

        def info(self, outcome: str, **fields: str | int) -> None:
            records.append((self._name, "info", outcome, fields))

        def warning(self, outcome: str, **fields: str | int) -> None:
            records.append((self._name, "warning", outcome, fields))

        def error(self, outcome: str, **fields: str | int) -> None:
            records.append((self._name, "error", outcome, fields))

    monkeypatch.setattr(issuer_module, "get_logger", Recorder)
    socket_path = short_dir / "teeserver.sock"
    mint = BlockingMint()
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())
    server.start()
    try:
        sock = _unix_connect(socket_path)
        body = token_request()
        sock.sendall(_post_head(len(body)) + body)
        assert mint.entered.acquire(timeout=5.0)
        sock.close()  # gone before the token is written: the reply hits EPIPE
        mint.release.set()
    finally:
        mint.release.set()
        server.stop()

    captured = capfd.readouterr()
    assert captured.err == ""
    assert TOKEN not in captured.out + captured.err
    assert records == [("sim", "warning", "SIM_REQUEST_FAILED", {})]


def test_socket_mode_change_never_follows_a_swapped_in_symlink(
    short_dir: Path, mint: RecordingMint, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = short_dir / "teeserver.sock"
    target = short_dir / "victim"
    target.write_text("private")
    target.chmod(0o600)
    original_bind = launcher_module._LauncherUnixServer.server_bind

    def bind_then_swap(server: socketserver.UnixStreamServer) -> None:
        original_bind(server)
        socket_path.unlink()
        socket_path.symlink_to(target)

    monkeypatch.setattr(launcher_module._LauncherUnixServer, "server_bind", bind_then_swap)
    server = LauncherServer(socket_path, mint=mint, limits=SimLimits())

    with pytest.raises(OSError, match="not a socket"):
        server.start()
    server.stop()

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert socket_path.is_symlink()
