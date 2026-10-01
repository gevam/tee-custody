"""Simulated Confidential Space launcher socket."""

import json
import re
import socketserver
import threading
from collections.abc import Callable, Sequence
from http import HTTPStatus
from pathlib import Path
from typing import Final, cast

from teecustody_sim.config import SimLimits
from teecustody_sim.issuer import _BoundedServer, _SimRequestHandler

_POLL_INTERVAL_S: Final = 0.05
_TOKEN_PATH: Final = "/v1/token"  # noqa: S105 - a URL path
_REQUEST_KEYS: Final = frozenset({"audience", "token_type", "nonces"})
_TOKEN_TYPE: Final = "OIDC"  # noqa: S105 - a token type name
# FACTS F-03: at most six nonces of 10-74 bytes (the intersection of the two documented ranges).
_MAX_NONCES: Final = 6
_NONCE_MIN_BYTES: Final = 10
_NONCE_MAX_BYTES: Final = 74
_DECIMAL: Final = re.compile(r"[0-9]+")

type _Mint = Callable[[str, Sequence[str]], str]


class _Rejected(Exception):
    """Ends a request with a fixed status and a fixed, input-free body."""

    def __init__(self, status: HTTPStatus, body: bytes) -> None:
        super().__init__(status)
        self.status = status
        self.body = body


class _InvalidRequest(_Rejected):
    """The request is not a valid token request."""

    def __init__(self) -> None:
        super().__init__(HTTPStatus.BAD_REQUEST, b"INVALID_REQUEST")


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    if len({key for key, _ in pairs}) != len(pairs):
        raise _InvalidRequest
    return dict(pairs)


def _reject_constant(name: str) -> object:
    raise _InvalidRequest


def _utf8_length(text: str) -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise _InvalidRequest from None


def _parse_token_request(body: bytes) -> tuple[str, list[str]]:
    """Strict F-02 request schema: exactly `audience`, `token_type`, `nonces`; F-03 nonce limits."""
    try:
        fields = json.loads(
            body.decode("utf-8"), object_pairs_hook=_unique_keys, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError):
        raise _InvalidRequest from None
    if not isinstance(fields, dict) or set(fields) != _REQUEST_KEYS:
        raise _InvalidRequest
    audience, nonces = fields["audience"], fields["nonces"]
    if not isinstance(audience, str) or _utf8_length(audience) == 0:
        raise _InvalidRequest
    if fields["token_type"] != _TOKEN_TYPE:
        raise _InvalidRequest
    if not isinstance(nonces, list) or len(nonces) > _MAX_NONCES:
        raise _InvalidRequest
    for nonce in nonces:
        if not isinstance(nonce, str):
            raise _InvalidRequest
        if not _NONCE_MIN_BYTES <= _utf8_length(nonce) <= _NONCE_MAX_BYTES:
            raise _InvalidRequest
    return audience, nonces


class _LauncherUnixServer(_BoundedServer, socketserver.UnixStreamServer):
    mint: _Mint


class _LauncherHandler(_SimRequestHandler):
    allowed_methods = "POST"

    def do_POST(self) -> None:
        # Framing first, then the bounded body is read, so every later reply follows a fully read
        # request (a reply sent while the client is still writing its body breaks the client).
        server = cast(_LauncherUnixServer, self.server)
        try:
            body = self._read_body(server.limits.max_request_bytes)
            if self.over_capacity:
                raise _Rejected(HTTPStatus.SERVICE_UNAVAILABLE, b"SERVICE_UNAVAILABLE")
            if self.path != _TOKEN_PATH:
                raise _Rejected(HTTPStatus.NOT_FOUND, b"NOT_FOUND")
            audience, nonces = _parse_token_request(body)
        except _Rejected as rejected:
            self.reply(rejected.status, rejected.body)
            return
        try:
            token = server.mint(audience, nonces)
        except Exception:  # noqa: BLE001 - a minting failure's detail is never echoed or logged
            self.reply(HTTPStatus.INTERNAL_SERVER_ERROR, b"INTERNAL_ERROR")
            return
        self.reply(HTTPStatus.OK, token.encode())

    def _read_body(self, max_bytes: int) -> bytes:
        lengths = self.headers.get_all("Content-Length")
        if lengths is None:
            raise _Rejected(HTTPStatus.LENGTH_REQUIRED, b"LENGTH_REQUIRED")
        if len(lengths) != 1 or not _DECIMAL.fullmatch(lengths[0]):
            raise _InvalidRequest
        length = int(lengths[0])
        if length > max_bytes:
            raise _Rejected(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"CONTENT_TOO_LARGE")
        body = self.rfile.read(length)
        if len(body) != length:
            raise _InvalidRequest
        return body


class LauncherServer:
    def __init__(
        self,
        socket_path: Path,
        *,
        mint: Callable[[str, Sequence[str]], str],
        limits: SimLimits,
    ) -> None:
        self._socket_path = socket_path
        self._mint = mint
        self._limits = limits
        self._server: _LauncherUnixServer | None = None

    def start(self) -> None:
        server = _LauncherUnixServer(str(self._socket_path), _LauncherHandler)
        # The real launcher's socket is connectable by the workload's (non-root) user.
        self._socket_path.chmod(0o666)
        server.bound(self._limits, _LauncherHandler)
        server.mint = self._mint
        self._server = server
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": _POLL_INTERVAL_S}, daemon=True
        ).start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._socket_path.unlink(missing_ok=True)
