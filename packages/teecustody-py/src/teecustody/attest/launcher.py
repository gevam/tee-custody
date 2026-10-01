"""Confidential Space launcher socket client.

The only token source of the workload (spec §11): an outbound HTTP/1.1 request over the
platform-provided Unix socket (FACTS F-01, F-02). Nothing here binds or listens. One monotonic
deadline (`timeout_s`) and one byte budget bound the whole exchange, interim 1xx replies included.
"""

import http.client
import json
import math
import socket
import time
from collections.abc import Buffer
from typing import Final

from teecustody.attest.nonce import launcher_nonce
from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.attest.token import parse_token_metadata

DEFAULT_LAUNCHER_SOCKET: Final = "/run/container_launcher/teeserver.sock"

_TOKEN_PATH: Final = "/v1/token"  # noqa: S105 - an endpoint path, FACTS F-02
_TOKEN_TYPE: Final = "OIDC"  # noqa: S105 - the only supported token type
_IDENTITY_NONCE_BYTES: Final = 32
_MAX_AUDIENCE_CHARS: Final = 2048
_MAX_HEAD_BYTES: Final = 16384  # status lines and headers, interim 1xx replies included


class _ResponseTooLarge(Exception):
    """The launcher sent more bytes than the response budget allows."""


class _BoundedSocket(socket.socket):
    """A Unix stream socket whose every operation shares one deadline and one receive budget."""

    def __init__(self, deadline: float, max_received: int) -> None:
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self._deadline = deadline
        self._max_received = max_received
        self._received = 0

    def arm(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.settimeout(remaining)

    def sendall(self, data: Buffer, flags: int = 0, /) -> None:
        self.arm()
        super().sendall(data, flags)

    def recv_into(self, buffer: Buffer, nbytes: int = 0, flags: int = 0) -> int:
        self.arm()
        received = super().recv_into(buffer, nbytes, flags)
        self._received += received
        if self._received > self._max_received:
            raise _ResponseTooLarge
        return received


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 to `Host: localhost` over the launcher's Unix socket; outbound only."""

    def __init__(self, socket_path: str, timeout_s: float, max_received: int) -> None:
        super().__init__("localhost")
        self._socket_path = socket_path
        self._deadline = time.monotonic() + timeout_s
        self._max_received = max_received

    def connect(self) -> None:
        sock = _BoundedSocket(self._deadline, self._max_received)
        try:
            sock.arm()
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


class ConfidentialSpaceLauncher:
    def __init__(
        self,
        socket_path: str = DEFAULT_LAUNCHER_SOCKET,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> None:
        if not (_is_number(timeout_s) and math.isfinite(timeout_s) and timeout_s > 0):
            raise LauncherError(LauncherErrorCode.INVALID_CONFIGURATION)
        if not (_is_int(max_response_bytes) and max_response_bytes > 0):
            raise LauncherError(LauncherErrorCode.INVALID_CONFIGURATION)
        self._socket_path = socket_path
        self._timeout_s = timeout_s
        self._max_response_bytes = max_response_bytes

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        if (
            token_type != _TOKEN_TYPE
            or len(identity_nonce) != _IDENTITY_NONCE_BYTES
            or not 0 < len(audience) <= _MAX_AUDIENCE_CHARS
        ):
            raise LauncherError(LauncherErrorCode.INVALID_CONFIGURATION)
        nonce = launcher_nonce(identity_nonce)
        body = json.dumps({"audience": audience, "nonces": [nonce], "token_type": token_type})
        status, raw = self._post(body)
        if status >= 500:
            raise LauncherError(LauncherErrorCode.UNAVAILABLE)
        if status != 200 or len(raw) > self._max_response_bytes:
            raise LauncherError(LauncherErrorCode.TOKEN_REJECTED)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise LauncherError(LauncherErrorCode.TOKEN_REJECTED) from None
        return parse_token_metadata(
            text,
            audience=audience,
            expected_nonce=nonce,
            max_token_bytes=self._max_response_bytes,
        )

    def _post(self, body: str) -> tuple[int, bytes]:
        """Send the token request; read at most `max_response_bytes + 1` bytes of the reply.

        Transport and HTTP framing failures, including a body cut short of its announced
        length, are UNAVAILABLE.
        """
        connection = _UnixHTTPConnection(
            self._socket_path,
            self._timeout_s,
            _MAX_HEAD_BYTES + self._max_response_bytes + 1,
        )
        try:
            connection.request(
                "POST", _TOKEN_PATH, body=body, headers={"Content-Type": "application/json"}
            )
            with connection.getresponse() as response:
                raw = response.read(self._max_response_bytes + 1)
                if len(raw) <= self._max_response_bytes and response.length:
                    raise http.client.IncompleteRead(raw, response.length)
                return response.status, raw
        except _ResponseTooLarge:
            raise LauncherError(LauncherErrorCode.TOKEN_REJECTED) from None
        except (OSError, http.client.HTTPException):
            raise LauncherError(LauncherErrorCode.UNAVAILABLE) from None
        finally:
            connection.close()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return _is_int(value) or isinstance(value, float)
