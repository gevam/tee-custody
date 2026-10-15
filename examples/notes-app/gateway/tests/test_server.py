"""T-40: gateway uvicorn server hardening (INC-2-API §6 "Server hardening"; SR-3, SR-4, SR-11).

Live tests run `uvicorn.Server(uvicorn_config(...))` in a thread on 127.0.0.1:0 and talk raw
sockets. Every wait is bounded, every socket is closed and every server is stopped on teardown.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol
from uvicorn.server import ServerState

from notes_gateway import GatewayLimits, create_app
from notes_gateway import server as gateway_server
from teecustody.obs import JsonLogFormatter
from teecustody.queue import PublishedBundle, ResponsePage

START_TIMEOUT_S = 10.0
STOP_TIMEOUT_S = 10.0
IO_BOUND_S = 5.0
PARTIAL_HEADERS = b"GET /bundles HTTP/1.1\r\nHost: x\r\nX-A: "
INSTANCE = "a1" * 16


class Relay:
    """A RelayQueue fake that counts calls; `list_bundles` sleeps `delay_s` first."""

    def __init__(self, delay_s: float = 0.0) -> None:
        self.calls = 0
        self.delay_s = delay_s

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        self.calls += 1
        time.sleep(self.delay_s)
        return []

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.calls += 1
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        self.calls += 1
        return ResponsePage((), None)


# ------------------------------------------------------------- criterion 10: the uvicorn settings
@pytest.fixture
def config_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real_config = uvicorn.Config

    class RecordingConfig(real_config):  # type: ignore[valid-type,misc]
        def __init__(self, app: Any, **kwargs: Any) -> None:
            calls.append(kwargs)
            super().__init__(app, **kwargs)

    monkeypatch.setattr(uvicorn, "Config", RecordingConfig)
    return calls


def test_uvicorn_config_has_every_section_6_setting(config_calls: list[dict[str, Any]]) -> None:
    app = create_app(Relay())

    config = gateway_server.uvicorn_config(app, host="127.0.0.1", port=0)

    assert len(config_calls) == 1
    assert config.app is app
    assert (config.host, config.port) == ("127.0.0.1", 0)
    assert isinstance(config.http, type)
    assert issubclass(config.http, H11Protocol)
    assert config.http is not H11Protocol
    assert config.ws == "none"
    assert config.proxy_headers is False
    assert config.server_header is False
    assert config.access_log is False
    assert config.h11_max_incomplete_event_size == 16384
    assert config.timeout_keep_alive == 5
    assert config.log_level == "warning"
    assert config.limit_concurrency is None
    assert "forwarded_allow_ips" not in config_calls[0]
    assert "limit_concurrency" not in config_calls[0]


def test_uvicorn_config_loads_the_gateway_protocol_and_no_websocket_protocol() -> None:
    config = gateway_server.uvicorn_config(create_app(Relay()), host="127.0.0.1", port=0)

    config.load()

    assert config.http_protocol_class is config.http
    assert config.ws_protocol_class is None


# ------------------------------------------------------------- criterion 9: limits validation
INVALID_LIMITS: list[dict[str, object]] = [
    {"header_read_timeout_s": 0.5},
    {"header_read_timeout_s": 60.5},
    {"header_read_timeout_s": float("nan")},
    {"header_read_timeout_s": float("inf")},
    {"header_read_timeout_s": True},
    {"header_read_timeout_s": "10"},
    {"max_connections": 0},
    {"max_connections": True},
    {"max_connections": 3.0},
    {"max_connections": 63},
    {"max_header_bytes": 1023},
    {"max_header_bytes": 12289},
    {"max_header_bytes": True},
    {"max_header_count": 15},
    {"max_header_count": 257},
    {"max_header_count": True},
    {"max_page": 0},
    {"cors_origins": ("*",)},
]
BOUNDARY_LIMITS: list[dict[str, object]] = [
    {"header_read_timeout_s": 1.0},
    {"header_read_timeout_s": 60.0},
    {"max_connections": 64},
    {"max_header_bytes": 1024},
    {"max_header_bytes": 12288},
    {"max_header_count": 16},
    {"max_header_count": 256},
]


@pytest.mark.parametrize("fields", INVALID_LIMITS, ids=repr)
def test_uvicorn_config_refuses_limits_that_create_app_refuses(fields: dict[str, object]) -> None:
    limits = GatewayLimits(**fields)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"^INVALID_(LIMITS|CORS_ORIGIN)$") as refused:
        create_app(Relay(), limits=limits)
    app = create_app(Relay())

    with pytest.raises(ValueError, match=r"^INVALID_(LIMITS|CORS_ORIGIN)$") as also_refused:
        gateway_server.uvicorn_config(app, limits=limits, host="127.0.0.1", port=0)

    assert str(also_refused.value) == str(refused.value)


@pytest.mark.parametrize("fields", BOUNDARY_LIMITS, ids=repr)
def test_uvicorn_config_accepts_boundary_limits(fields: dict[str, object]) -> None:
    limits = GatewayLimits(**fields)  # type: ignore[arg-type]
    app = create_app(Relay(), limits=limits)

    config = gateway_server.uvicorn_config(app, limits=limits, host="127.0.0.1", port=0)

    assert issubclass(config.http, H11Protocol)


# ------------------------------------------------------------- live server harness
class Records(logging.Handler):
    """Collects the rendered JSON of every record it sees."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.setFormatter(JsonLogFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def outcomes(self) -> list[str]:
        return [r.getMessage() for r in self.records if r.name == "teecustody.gateway"]

    def rendered(self) -> list[str]:
        return [self.format(r) for r in self.records]


class LiveGateway:
    """The gateway under `uvicorn.Server(uvicorn_config(...))` in a thread on 127.0.0.1:0."""

    def __init__(self, relay: Relay, limits: GatewayLimits, records: Records) -> None:
        self.relay = relay
        app = create_app(relay, limits=limits)
        self.config = gateway_server.uvicorn_config(app, limits=limits, host="127.0.0.1", port=0)
        # uvicorn's dictConfig ran in Config(); attach afterwards so it cannot drop the handler.
        logging.getLogger("uvicorn.error").addHandler(records)
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.sockets: list[socket.socket] = []
        self.port = 0

    def start(self) -> LiveGateway:
        self.thread.start()
        deadline = time.perf_counter() + START_TIMEOUT_S
        while not self.server.started:
            assert self.thread.is_alive(), "server thread exited before it started"
            assert time.perf_counter() < deadline, "server did not start within 10 s"
            time.sleep(0.01)
        self.port = self.server.servers[0].sockets[0].getsockname()[1]
        return self

    def connect(self) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=IO_BOUND_S)
        self.sockets.append(sock)
        return sock

    def open_connections(self) -> int:
        return len(self.server.server_state.connections)

    def wait_connections(self, count: int, bound_s: float = IO_BOUND_S) -> None:
        deadline = time.perf_counter() + bound_s
        while self.open_connections() != count:
            assert time.perf_counter() < deadline, f"open connections never reached {count}"
            time.sleep(0.005)

    def stop(self) -> None:
        for sock in self.sockets:
            sock.close()
        self.server.should_exit = True
        self.thread.join(STOP_TIMEOUT_S)
        if self.thread.is_alive():  # pragma: no cover - only a broken server gets here
            self.server.force_exit = True
            self.thread.join(STOP_TIMEOUT_S)
        assert not self.thread.is_alive()


@pytest.fixture
def records() -> Iterator[Records]:
    handler = Records()
    base = logging.getLogger("teecustody")
    saved = base.level
    base.setLevel(logging.INFO)
    base.addHandler(handler)
    try:
        yield handler
    finally:
        base.removeHandler(handler)
        base.setLevel(saved)
        logging.getLogger("uvicorn.error").removeHandler(handler)


@pytest.fixture
def gateway(records: Records) -> Iterator[Callable[..., LiveGateway]]:
    started: list[LiveGateway] = []

    def start(relay: Relay | None = None, **limits: Any) -> LiveGateway:
        live = LiveGateway(relay or Relay(), GatewayLimits(**limits), records)
        started.append(live)
        return live.start()

    try:
        yield start
    finally:
        for live in started:
            live.stop()


def read_to_eof(sock: socket.socket, start: float, bound_s: float) -> tuple[bytes, float]:
    """Every byte until the peer closes, and the close time relative to `start`. A reset counts
    as the close. Fails if the peer has not closed `bound_s` after `start`."""
    data = bytearray()
    while True:
        remaining = start + bound_s - time.perf_counter()
        assert remaining > 0, f"no EOF within {bound_s} s"
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(65536)
        except TimeoutError:
            pytest.fail(f"no EOF within {bound_s} s")
        except ConnectionResetError:
            chunk = b""
        if not chunk:
            return bytes(data), time.perf_counter() - start
        data += chunk


def read_response(sock: socket.socket, bound_s: float = IO_BOUND_S) -> tuple[int, bytes]:
    """One HTTP/1.1 response with a Content-Length body: (status, body)."""
    deadline = time.perf_counter() + bound_s
    data = bytearray()

    def fill() -> None:
        remaining = deadline - time.perf_counter()
        assert remaining > 0, "response incomplete"
        sock.settimeout(remaining)
        chunk = sock.recv(65536)
        assert chunk, "connection closed mid-response"
        data.extend(chunk)

    while b"\r\n\r\n" not in data:
        fill()
    head, _, _ = bytes(data).partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    headers = dict(line.lower().split(b": ", 1) for line in lines[1:])
    length = int(headers[b"content-length"])
    while len(data) < len(head) + 4 + length:
        fill()
    body = bytes(data[len(head) + 4 : len(head) + 4 + length])
    leftover = bytes(data[len(head) + 4 + length :])
    assert leftover == b"", "read past one response"
    return int(lines[0].split(b" ")[1]), body


# ------------------------------------------------------------- criteria 1-3: header-read deadline
def test_partial_headers_are_closed_silently_at_the_header_deadline(
    gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway(header_read_timeout_s=1.0)
    sock = live.connect()
    start = time.perf_counter()
    sock.sendall(PARTIAL_HEADERS)

    data, closed_at = read_to_eof(sock, start, 3.0)

    assert data == b""
    assert 0.9 <= closed_at <= 3.0
    assert live.relay.calls == 0
    assert records.outcomes() == ["GATEWAY_HEADER_TIMEOUT"]


def test_an_idle_connection_that_sends_nothing_is_closed_at_the_header_deadline(
    gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway(header_read_timeout_s=1.0)
    sock = live.connect()
    start = time.perf_counter()

    data, closed_at = read_to_eof(sock, start, 3.0)

    assert data == b""
    assert 0.9 <= closed_at <= 3.0
    assert records.outcomes() == ["GATEWAY_HEADER_TIMEOUT"]


def _trickle(
    sock: socket.socket, payload: bytes, start: float, gap_s: float, bound_s: float
) -> float:
    """Send `payload` one byte every `gap_s` until the peer closes; the close time after `start`.
    Fails if the peer is still open `bound_s` after `start`."""
    for byte in payload:
        try:
            sock.sendall(bytes([byte]))
        except (BrokenPipeError, ConnectionResetError):
            return time.perf_counter() - start
        sock.settimeout(gap_s)
        try:
            chunk = sock.recv(1)
        except TimeoutError:
            assert time.perf_counter() - start <= bound_s, f"still open after {bound_s} s"
            continue
        except ConnectionResetError:
            chunk = b""
        assert chunk == b"", "the server wrote bytes to a timed-out connection"
        return time.perf_counter() - start
    pytest.fail("payload exhausted before the server closed")


def test_the_header_deadline_is_total_and_not_reset_by_trickled_bytes(
    gateway: Callable[..., LiveGateway],
) -> None:
    live = gateway(header_read_timeout_s=1.0)
    sock = live.connect()
    start = time.perf_counter()

    closed_at = _trickle(sock, PARTIAL_HEADERS + b"a" * 64, start, 0.25, 3.0)

    assert 0.9 <= closed_at <= 3.0


# ------------------------------------------------------------- criterion 5: complete headers
REQUEST_TIMEOUT = b'{"code":"REQUEST_TIMEOUT"}'


def test_once_headers_are_complete_only_the_body_deadline_applies(
    gateway: Callable[..., LiveGateway],
) -> None:
    live = gateway(header_read_timeout_s=1.0, body_read_timeout_s=3.0)
    sock = live.connect()
    start = time.perf_counter()
    sock.sendall(
        f"POST /requests/{INSTANCE} HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: application/octet-stream\r\nContent-Length: 10\r\n\r\nx".encode()
    )

    status, body = read_response(sock, 6.0)
    answered_at = time.perf_counter() - start

    assert (status, body) == (408, REQUEST_TIMEOUT)
    assert 2.5 <= answered_at <= 5.0
    assert live.relay.calls == 0


def test_a_route_slower_than_the_header_deadline_still_answers(
    gateway: Callable[..., LiveGateway],
) -> None:
    live = gateway(Relay(delay_s=2.0), header_read_timeout_s=1.0)
    sock = live.connect()
    sock.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n")

    assert read_response(sock, 6.0) == (200, b'{"bundles":[]}')


# ------------------------------------------------------------- criterion 4: kept-alive connections
def test_the_deadline_restarts_after_a_response_on_a_kept_alive_connection(
    gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway(header_read_timeout_s=1.0)
    sock = live.connect()
    sock.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n")
    assert read_response(sock) == (200, b'{"bundles":[]}')
    start = time.perf_counter()

    closed_at = _trickle(sock, PARTIAL_HEADERS + b"a" * 64, start, 0.25, 3.0)

    assert closed_at <= 3.0
    assert live.relay.calls == 1
    assert records.outcomes() == ["GATEWAY_OK", "GATEWAY_HEADER_TIMEOUT"]


# ------------------------------------------------------------- criterion 6: pipelining
def test_two_pipelined_requests_in_one_write_both_get_200(
    gateway: Callable[..., LiveGateway],
) -> None:
    live = gateway(Relay(delay_s=1.5), header_read_timeout_s=1.0)
    sock = live.connect()
    sock.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n" * 2)

    first = read_response(sock, 6.0)
    second = read_response(sock, 6.0)

    assert first == second == (200, b'{"bundles":[]}')
    assert live.relay.calls == 2


# ------------------------------------------------------------- criterion 7: connection cap
def test_a_connection_beyond_max_connections_is_closed_at_once_and_others_are_unaffected(
    gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway(
        max_concurrency=4, per_source_max_in_flight=4, max_connections=4, header_read_timeout_s=10.0
    )
    held = [live.connect() for _ in range(4)]
    live.wait_connections(4)
    excess = live.connect()
    start = time.perf_counter()

    data, closed_at = read_to_eof(excess, start, 0.5)

    assert data == b""
    assert closed_at <= 0.5
    assert records.outcomes() == ["GATEWAY_CONNECTION_LIMIT"]
    live.wait_connections(4)
    held[0].close()
    live.wait_connections(3)
    fresh = live.connect()
    fresh.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n")
    assert read_response(fresh) == (200, b'{"bundles":[]}')
    for sock in held[1:]:
        sock.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n")
        assert read_response(sock) == (200, b'{"bundles":[]}')
    assert records.outcomes().count("GATEWAY_CONNECTION_LIMIT") == 1


# ------------------------------------------------------------- criterion 8: parse failures
PARSE_FAILURE_400 = (
    b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: 27\r\n"
    b"cache-control: no-store\r\nx-content-type-options: nosniff\r\nconnection: close\r\n\r\n"
    b'{"code":"INVALID_ARGUMENT"}'
)
PARSE_FAILURES = {
    "c: header named Bad Header": b"GET /bundles HTTP/1.1\r\nHost: x\r\nBad Header: v\r\n\r\n",
    "d: TLS ClientHello prefix": bytes.fromhex("16 03 01 00 c4 01 00 00 c0 03 03") + bytes(40),
    "e: missing Host": b"GET /bundles HTTP/1.1\r\n\r\n",
    "e: missing Host, Connection: close": b"GET /bundles HTTP/1.1\r\nConnection: close\r\n\r\n",
    "f: incomplete 20000-byte value": b"GET /bundles HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 20000,
}
# Nothing of the input, the path or the peer may appear in any log record (SR-3, SR-11).
LEAK_MARKERS = ("Bad Header", "bundles", "X-Big", "GARBAGE", "aaaa", "127.0.0.1", "Host")


def _assert_nothing_leaked(records: Records) -> None:
    for line in records.rendered():
        for marker in LEAK_MARKERS:
            assert marker not in line


@pytest.mark.parametrize("payload", PARSE_FAILURES.values(), ids=PARSE_FAILURES.keys())
def test_a_request_the_parser_rejects_gets_exactly_the_json_400_then_eof(
    payload: bytes, gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway()
    sock = live.connect()
    start = time.perf_counter()
    sock.sendall(payload)

    data, _ = read_to_eof(sock, start, IO_BOUND_S)

    assert data == PARSE_FAILURE_400
    assert live.relay.calls == 0
    assert records.outcomes() == ["GATEWAY_INVALID_ARGUMENT"]
    _assert_nothing_leaked(records)


def test_garbage_after_a_kept_alive_200_gets_exactly_the_json_400_then_eof(
    gateway: Callable[..., LiveGateway], records: Records
) -> None:
    live = gateway()
    sock = live.connect()
    sock.sendall(b"GET /bundles HTTP/1.1\r\nHost: x\r\n\r\n")
    assert read_response(sock) == (200, b'{"bundles":[]}')
    start = time.perf_counter()
    sock.sendall(b"GARBAGE\x00\x01\r\n\r\n")

    data, _ = read_to_eof(sock, start, IO_BOUND_S)

    assert data == PARSE_FAILURE_400
    assert live.relay.calls == 1
    assert records.outcomes() == ["GATEWAY_OK", "GATEWAY_INVALID_ARGUMENT"]
    _assert_nothing_leaked(records)


# ------------------------------------------------------------- criterion 11: protocol hooks (fakes)
class FakeHandle:
    def __init__(self, delay: float, callback: Callable[..., object], args: tuple[object, ...]):
        self.delay = delay
        self.callback = callback
        self.args = args
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def fire(self) -> None:
        self.callback(*self.args)


class FakeLoop:
    """The only loop method the protocol hooks use without a request: `call_later`."""

    def __init__(self) -> None:
        self.handles: list[FakeHandle] = []

    def call_later(
        self, delay: float, callback: Callable[..., object], *args: object
    ) -> FakeHandle:
        handle = FakeHandle(delay, callback, args)
        self.handles.append(handle)
        return handle


class FakeTransport:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closes = 0
        self.closing = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closes += 1
        self.closing = True

    def is_closing(self) -> bool:
        return self.closing

    def get_extra_info(self, name: str, default: object = None) -> object:
        return default

    def pause_reading(self) -> None:
        pass

    def resume_reading(self) -> None:
        pass


HOOK_TIMEOUT_S = 7.0


def _protocol(
    *, max_connections: int = 64, others: int = 0
) -> tuple[Any, FakeLoop, FakeTransport, ServerState]:
    limits = GatewayLimits(header_read_timeout_s=HOOK_TIMEOUT_S, max_connections=max_connections)
    config = gateway_server.uvicorn_config(
        create_app(Relay(), limits=limits), limits=limits, host="127.0.0.1", port=0
    )
    loop, transport, state = FakeLoop(), FakeTransport(), ServerState()
    state.connections.update(object() for _ in range(others))  # type: ignore[misc]
    protocol = config.http(config=config, server_state=state, app_state={}, _loop=loop)
    protocol.connection_made(transport)
    return protocol, loop, transport, state


def test_connection_made_arms_one_deadline_for_the_current_cycle(records: Records) -> None:
    _proto, loop, transport, _ = _protocol()

    [handle] = loop.handles
    assert handle.delay == HOOK_TIMEOUT_S
    assert handle.args == (None,)
    assert (transport.written, transport.closes, records.outcomes()) == ([], 0, [])


def test_the_deadline_closes_an_unchanged_cycle_without_writing(records: Records) -> None:
    _proto, loop, transport, _ = _protocol()

    loop.handles[0].fire()

    assert (transport.written, transport.closes) == ([], 1)
    assert records.outcomes() == ["GATEWAY_HEADER_TIMEOUT"]


def test_connection_lost_cancels_the_pending_deadline() -> None:
    protocol, loop, _transport, _ = _protocol()

    protocol.connection_lost(None)

    assert loop.handles[0].cancelled


def test_the_deadline_does_nothing_once_a_new_cycle_exists(records: Records) -> None:
    protocol, loop, transport, _ = _protocol()
    protocol.cycle = SimpleNamespace(response_started=False, response_complete=False)

    loop.handles[0].fire()

    assert (transport.written, transport.closes, records.outcomes()) == ([], 0, [])


def test_the_deadline_does_nothing_on_a_closing_transport(records: Records) -> None:
    _proto, loop, transport, _ = _protocol()
    transport.closing = True

    loop.handles[0].fire()

    assert (transport.written, transport.closes, records.outcomes()) == ([], 0, [])


def test_response_completion_on_a_closing_transport_arms_nothing() -> None:
    protocol, loop, transport, _ = _protocol()
    transport.closing = True

    protocol.on_response_complete()

    assert len(loop.handles) == 1
    assert not loop.handles[0].cancelled


def test_response_completion_rearms_for_the_completed_cycle_before_uvicorn_runs() -> None:
    protocol, loop, _transport, state = _protocol()
    completed = SimpleNamespace(response_started=True, response_complete=True)
    protocol.cycle = completed

    protocol.on_response_complete()

    first, rearmed, keep_alive = loop.handles
    assert first.cancelled
    assert (rearmed.delay, rearmed.args, rearmed.cancelled) == (HOOK_TIMEOUT_S, (completed,), False)
    assert keep_alive.delay == 5
    assert state.total_requests == 1


@pytest.mark.parametrize(
    ("cycle", "written"),
    [
        (None, [PARSE_FAILURE_400]),
        (SimpleNamespace(response_started=True, response_complete=False), []),
        (SimpleNamespace(response_started=False, response_complete=False), [PARSE_FAILURE_400]),
        (SimpleNamespace(response_started=True, response_complete=True), [PARSE_FAILURE_400]),
    ],
    ids=["no cycle", "started, not complete", "not started", "started and complete"],
)
def test_send_400_response_never_interleaves_with_a_response_in_progress(
    cycle: SimpleNamespace | None, written: list[bytes], records: Records
) -> None:
    protocol, _loop, transport, _ = _protocol()
    protocol.cycle = cycle

    protocol.send_400_response("Invalid HTTP request received.")

    assert transport.written == written
    assert transport.closes == 1
    assert records.outcomes() == ["GATEWAY_INVALID_ARGUMENT"]


@pytest.mark.parametrize(("others", "closed"), [(63, False), (64, True)])
def test_connection_made_closes_only_beyond_max_connections(
    others: int, closed: bool, records: Records
) -> None:
    _proto, loop, transport, _ = _protocol(max_connections=64, others=others)

    assert transport.closes == int(closed)
    assert transport.written == []
    assert len(loop.handles) == int(not closed)
    assert records.outcomes() == (["GATEWAY_CONNECTION_LIMIT"] if closed else [])
