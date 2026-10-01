"""Loopback OIDC issuer: discovery document and JWKS."""

import io
import json
import socket
import socketserver
import threading
from collections.abc import Callable, Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar, Final, Protocol, cast

from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import SimConfigError, SimConfigErrorCode, SimLimits

_DISCOVERY_PATH: Final = "/.well-known/openid-configuration"
_JWKS_PATH: Final = "/jwks"
_POLL_INTERVAL_S: Final = 0.05
# Per-connection socket timeout (SR-4): a stalled client cannot hold a handler thread.
_REQUEST_DEADLINE_S = 10.0
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


class _IssuerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    limits: SimLimits
    routes: dict[str, bytes]

    def server_bind(self) -> None:
        # HTTPServer.server_bind resolves the host name; the simulator never needs it.
        socketserver.TCPServer.server_bind(self)


class _IssuerHTTPServer6(_IssuerHTTPServer):
    address_family = socket.AF_INET6


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


class _LimitedServer(Protocol):
    limits: SimLimits


class _SimRequestHandler(BaseHTTPRequestHandler):
    """Shared request handling: bounded head, fixed responses, 405 for any method without `do_`."""

    allowed_methods: ClassVar[str]

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(_REQUEST_DEADLINE_S)
        limits = cast(_LimitedServer, self.server).limits
        self.rfile = _HeadBudgetReader(self.rfile, limits.max_request_bytes)

    def handle_one_request(self) -> None:
        self.close_connection = True
        self.request_version = self.protocol_version
        self.requestline = ""
        try:
            super().handle_one_request()
        except _HeadTooLarge:
            self.reply(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE, b"REQUEST_HEAD_TOO_LARGE")

    def reply(self, status: HTTPStatus, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if status is HTTPStatus.METHOD_NOT_ALLOWED:
            self.send_header("Allow", self.allowed_methods)
        self.end_headers()
        self.wfile.write(body)

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
        body = cast(_IssuerHTTPServer, self.server).routes.get(self.path)
        if body is None:
            self.reply(HTTPStatus.NOT_FOUND, b"NOT_FOUND")
            return
        self.reply(HTTPStatus.OK, body, "application/json")


class IssuerServer:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        issuer: str,
        jwks: Mapping[str, JsonValue],
        limits: SimLimits,
    ) -> None:
        self._host = host
        self._port = port
        self._issuer = issuer
        self._jwks = _public_jwks(jwks)
        self._limits = limits
        self._server: _IssuerHTTPServer | None = None
        self._origin: str | None = None

    def start(self) -> None:
        ipv6 = ":" in self._host
        server_class = _IssuerHTTPServer6 if ipv6 else _IssuerHTTPServer
        server = server_class((self._host, self._port), _IssuerHandler)
        server.limits = self._limits
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
        server.routes = {
            _DISCOVERY_PATH: json.dumps(discovery).encode(),
            _JWKS_PATH: json.dumps(self._jwks).encode(),
        }
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
