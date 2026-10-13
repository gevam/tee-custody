"""Loopback OIDC issuer: discovery document and JWKS."""

import contextlib
import io
import json
import re
import socket
import socketserver
import threading
import time
from collections.abc import Buffer, Callable, Mapping, Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar, Final, cast

from teecustody.obs import get_logger
from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import SimConfigError, SimConfigErrorCode, SimLimits

_DISCOVERY_PATH: Final = "/.well-known/openid-configuration"
_JWKS_PATH: Final = "/jwks"
ATTACKER_JWKS_PATH: Final = "/attacker/jwks"
# CI-2-4 echo rule (INC-2-API §16.3). The pattern admits only 0x21-0x7E, so together with the
# length bound it is the whole validity test; a valid value is echoed byte for byte.
_ECHO_ORIGIN: Final = re.compile(
    r"(?:https?://(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?|null)", re.ASCII
)
_MAX_ORIGIN_BYTES: Final = 256
_POLL_INTERVAL_S: Final = 0.05
# One total deadline per connection for reading the request (SR-4): a slow or stalled client
# cannot hold a handler thread, however it paces its bytes.
_REQUEST_DEADLINE_S = 10.0
_MIN_SOCKET_TIMEOUT_S: Final = 0.001
_LOGGER_NAME: Final = "sim"
_CLAIMS_SUPPORTED: Final = (
    "aud",
    "dbgstat",
    "eat_nonce",
    "exp",
    "hwmodel",
    "iat",
    "iss",
    "nbf",
    "secboot",
    "submods",
    "swname",
)
_PUBLIC_JWK_MEMBERS: Final = ("kty", "alg", "use", "kid", "n", "e")

type _Request = socket.socket | tuple[bytes, socket.socket]
type _Address = tuple[str, int] | str


def _public_jwks(jwks: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Copy only public RSA members (SR-7): a private JWK member is never served."""
    keys = jwks.get("keys")
    if set(jwks) != {"keys"} or not isinstance(keys, list):
        raise ValueError("INVALID_JWKS")
    public: list[JsonValue] = []
    for key in keys:
        if not isinstance(key, dict):
            raise ValueError("INVALID_JWKS")
        public.append({name: key[name] for name in _PUBLIC_JWK_MEMBERS if name in key})
    return {"keys": public}


class _BoundedServer(socketserver.BaseServer):
    """Bounded thread-per-connection serving (SR-4), shared by the issuer and the launcher.

    Each accepted connection takes a slot (`max_concurrent_requests`) or, when none is free, an
    overflow slot (as many again) whose handler answers 503. Beyond both, the connection is closed
    at accept time. A slot is released after the handler returns (response flushed) and before
    the connection is shut down, so a client that has seen EOF is guaranteed that its slot is free.
    Threads holding slots are therefore at most 2 x `max_concurrent_requests`, plus threads that
    have released their slot and are only closing their connection; each is bounded by
    `_REQUEST_DEADLINE_S` plus the handler's own work.
    """

    request_queue_size = 128  # a burst waits to be accepted instead of failing at connect()
    busy_reply: bytes | None = None  # sent, never read for, beyond both slot kinds
    limits: SimLimits
    _threads: tuple[threading.Thread, ...] = ()  # also read by server_close after a failed bind

    def bound(self, limits: SimLimits, handler: type[socketserver.BaseRequestHandler]) -> None:
        self.limits = limits
        self._slots = threading.BoundedSemaphore(limits.max_concurrent_requests)
        self._overflow = threading.BoundedSemaphore(limits.max_concurrent_requests)
        self._handler = handler
        self._overflow_handler = type(
            "Overflow" + handler.__name__, (handler,), {"over_capacity": True}
        )

    def process_request(self, request: _Request, client_address: _Address) -> None:
        if self._slots.acquire(blocking=False):
            slot, handler = self._slots, self._handler
        elif self._overflow.acquire(blocking=False):
            slot, handler = self._overflow, self._overflow_handler
        else:
            self._send_busy_reply(request)
            self.shutdown_request(request)
            return
        thread = threading.Thread(
            target=self._serve_one, args=(request, client_address, slot, handler), daemon=True
        )
        self._threads = (*(alive for alive in self._threads if alive.is_alive()), thread)
        thread.start()

    def _send_busy_reply(self, request: _Request) -> None:
        """Best effort: never blocks, reads nothing and costs no thread."""
        if self.busy_reply is None:
            return
        with contextlib.suppress(OSError):
            cast(socket.socket, request).send(self.busy_reply, socket.MSG_DONTWAIT)

    def _serve_one(
        self,
        request: _Request,
        client_address: _Address,
        slot: threading.BoundedSemaphore,
        handler: type[socketserver.BaseRequestHandler],
    ) -> None:
        try:
            handler(request, client_address, self)
        except Exception:  # noqa: BLE001 - reported as a fixed code by handle_error
            self.handle_error(request, client_address)
        finally:
            try:
                slot.release()
            finally:
                self.shutdown_request(request)

    def handle_error(self, request: _Request, client_address: _Address) -> None:
        """A fixed outcome code only: the stock handler prints a traceback, bypassing obs."""
        get_logger(_LOGGER_NAME).warning("SIM_REQUEST_FAILED")

    def server_close(self) -> None:
        super().server_close()
        for thread in self._threads:
            thread.join()


class _IssuerHTTPServer(_BoundedServer, HTTPServer):
    routes: dict[str, bytes]
    cors_routes: dict[str, bytes]  # JWKS routes: Google CORS parity (ADR 0012 rule 5)

    def server_bind(self) -> None:
        # HTTPServer.server_bind resolves the host name; the simulator never needs it.
        socketserver.TCPServer.server_bind(self)


class _IssuerHTTPServer6(_IssuerHTTPServer):
    address_family = socket.AF_INET6


class _DeadlineSocketReader(io.RawIOBase):
    """Raw reader whose every `recv` waits at most until one fixed deadline."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Buffer, /) -> int:
        remaining = self._deadline - time.monotonic()
        self._sock.settimeout(max(remaining, _MIN_SOCKET_TIMEOUT_S))
        return self._sock.recv_into(buffer)


class _HeadTooLarge(Exception):
    """The request line plus headers exceeded `SimLimits.max_request_bytes`."""


class _HeadBudgetReader(io.BufferedIOBase):
    """Counts every byte `readline` returns (request line and headers) against a fixed budget.

    `read` (used only for a bounded body) is not counted. Not an `HTTPException`, so it escapes
    `BaseHTTPRequestHandler.parse_request` and reaches `_SimRequestHandler.handle_one_request`.
    """

    def __init__(self, inner: io.BufferedIOBase, budget: int) -> None:
        super().__init__()
        self._inner = inner
        self._remaining = budget

    def readline(self, size: int | None = -1, /) -> bytes:
        cap = self._remaining + 1 if size is None or size < 0 else min(size, self._remaining + 1)
        line = self._inner.readline(cap)
        self._remaining -= len(line)
        if self._remaining < 0:
            raise _HeadTooLarge
        return line

    def read(self, size: int | None = -1, /) -> bytes:
        return self._inner.read(size)


class _SimRequestHandler(BaseHTTPRequestHandler):
    """Shared request handling: bounded head, fixed responses, 405 for any method without `do_`."""

    allowed_methods: ClassVar[str]
    over_capacity: ClassVar[bool] = False

    def setup(self) -> None:
        super().setup()
        self.rfile.close()
        deadline = time.monotonic() + _REQUEST_DEADLINE_S
        reader = io.BufferedReader(_DeadlineSocketReader(self.connection, deadline))
        limits = cast(_BoundedServer, self.server).limits
        self.rfile = _HeadBudgetReader(reader, limits.max_request_bytes)

    def handle_one_request(self) -> None:
        self.close_connection = True
        self.request_version = self.protocol_version
        self.requestline = ""
        try:
            super().handle_one_request()
        except _HeadTooLarge:
            self.reply(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, b"REQUEST_HEAD_TOO_LARGE")

    def reply(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str | None = "text/plain",
        headers: Sequence[tuple[str, str]] = (),
    ) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        if status is HTTPStatus.METHOD_NOT_ALLOWED:
            self.send_header("Allow", self.allowed_methods)
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Stdlib parse errors: a fixed body naming the status, never the request (no HTML)."""
        status = HTTPStatus(code)
        self.close_connection = True
        self.request_version = self.protocol_version  # always a status line, even for HTTP/0.9
        self.reply(status, status.name.encode())

    def log_message(self, format: str, *args: object) -> None:
        """No access log: request lines are untrusted input and are never written out."""

    def __getattr__(self, name: str) -> Callable[[], None]:
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)

    def _method_not_allowed(self) -> None:
        self.reply(HTTPStatus.METHOD_NOT_ALLOWED, b"METHOD_NOT_ALLOWED")


class _IssuerHandler(_SimRequestHandler):
    allowed_methods = "GET"

    def do_GET(self) -> None:
        if self.over_capacity:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, b"SERVICE_UNAVAILABLE")
            return
        server = cast(_IssuerHTTPServer, self.server)
        if self.path in server.cors_routes:
            body = server.cors_routes[self.path]
            self.reply(HTTPStatus.OK, body, "application/json", self._cors_headers())
        elif self.path in server.routes:
            self.reply(HTTPStatus.OK, server.routes[self.path], "application/json")
        else:
            self.reply(HTTPStatus.NOT_FOUND, b"NOT_FOUND")

    def do_OPTIONS(self) -> None:
        """A preflight on a JWKS route; any other path keeps the 405 every other method gets."""
        if self.path not in cast(_IssuerHTTPServer, self.server).cors_routes:
            self._method_not_allowed()
            return
        if self.over_capacity:
            self.reply(HTTPStatus.SERVICE_UNAVAILABLE, b"SERVICE_UNAVAILABLE")
            return
        self.reply(HTTPStatus.OK, b"", None, self._cors_headers(preflight=True))

    def _cors_headers(self, *, preflight: bool = False) -> list[tuple[str, str]]:
        """`Vary: Origin`; with one valid `Origin`, its exact echo (and, on a preflight, `GET`)."""
        headers = [("Vary", "Origin")]
        origin = self._echoable_origin()
        if origin is not None:
            headers.append(("Access-Control-Allow-Origin", origin))
            if preflight:
                headers.append(("Access-Control-Allow-Methods", "GET"))
        return headers

    def _echoable_origin(self) -> str | None:
        """The request's only `Origin` value if it passes the CI-2-4 rule; nothing else is read.

        A bare CR splits a header line in the stdlib parser and is recorded only as a defect: the
        value it leaves behind is not the value the client sent, so nothing is echoed.
        """
        origins = self.headers.get_all("Origin") or []
        if (
            self.headers.defects
            or len(origins) != 1
            or len(origins[0].encode("latin-1")) > _MAX_ORIGIN_BYTES
            or _ECHO_ORIGIN.fullmatch(origins[0]) is None
        ):
            return None
        return origins[0]


class IssuerServer:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        issuer: str,
        jwks: Mapping[str, JsonValue],
        limits: SimLimits,
        attacker_jwks: Mapping[str, JsonValue] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._issuer = issuer
        self._jwks = _public_jwks(jwks)
        self._attacker_jwks = None if attacker_jwks is None else _public_jwks(attacker_jwks)
        self._limits = limits
        self._server: _IssuerHTTPServer | None = None
        self._origin: str | None = None

    def start(self) -> None:
        ipv6 = ":" in self._host
        server_class = _IssuerHTTPServer6 if ipv6 else _IssuerHTTPServer
        server = server_class((self._host, self._port), _IssuerHandler)
        server.bound(self._limits, _IssuerHandler)
        host = f"[{self._host}]" if ipv6 else self._host
        origin = f"http://{host}:{server.server_address[1]}"
        discovery: dict[str, JsonValue] = {
            "issuer": self._issuer,
            "jwks_uri": origin + _JWKS_PATH,
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["id_token"],
            "subject_types_supported": ["public"],
            "scopes_supported": ["openid"],
            "claims_supported": list(_CLAIMS_SUPPORTED),
        }
        server.routes = {_DISCOVERY_PATH: json.dumps(discovery).encode()}
        server.cors_routes = {_JWKS_PATH: json.dumps(self._jwks).encode()}
        if self._attacker_jwks is not None:
            server.cors_routes[ATTACKER_JWKS_PATH] = json.dumps(self._attacker_jwks).encode()
        self._server = server
        self._origin = origin
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": _POLL_INTERVAL_S}, daemon=True
        ).start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    @property
    def origin(self) -> str:
        if self._origin is None:
            raise SimConfigError(SimConfigErrorCode.STATE_NOT_INITIALISED)
        return self._origin
