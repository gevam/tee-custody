"""Confidential Space launcher socket client.

The only token source of the workload (spec §11): an outbound HTTP/1.1 request over the
platform-provided Unix socket (FACTS F-01, F-02). Nothing here binds or listens.
"""

import http.client
import json
import socket
from typing import Final

from teecustody.attest.nonce import launcher_nonce
from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.attest.token import parse_token_metadata

DEFAULT_LAUNCHER_SOCKET: Final = "/run/container_launcher/teeserver.sock"

_TOKEN_PATH: Final = "/v1/token"  # noqa: S105 - an endpoint path, FACTS F-02
_TOKEN_TYPE: Final = "OIDC"  # noqa: S105 - the only supported token type
_IDENTITY_NONCE_BYTES: Final = 32
_MAX_AUDIENCE_CHARS: Final = 2048


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 to `Host: localhost` over the launcher's Unix socket; outbound only."""

    def __init__(self, socket_path: str, timeout_s: float) -> None:
        super().__init__("localhost", timeout=timeout_s)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
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
        connection = _UnixHTTPConnection(self._socket_path, self._timeout_s)
        try:
            connection.request(
                "POST", _TOKEN_PATH, body=body, headers={"Content-Type": "application/json"}
            )
            with connection.getresponse() as response:
                raw = response.read(self._max_response_bytes + 1)
                if len(raw) <= self._max_response_bytes and response.length:
                    raise http.client.IncompleteRead(raw, response.length)
                return response.status, raw
        except (OSError, http.client.HTTPException):
            raise LauncherError(LauncherErrorCode.UNAVAILABLE) from None
        finally:
            connection.close()
