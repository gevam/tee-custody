"""Confidential Space launcher socket client."""

import http.client
import json
import socket
from typing import Final

from teecustody.attest.nonce import launcher_nonce
from teecustody.attest.ports import AttestationToken
from teecustody.attest.token import parse_token_metadata

DEFAULT_LAUNCHER_SOCKET: Final = "/run/container_launcher/teeserver.sock"

_TOKEN_PATH: Final = "/v1/token"  # noqa: S105 - an endpoint path, FACTS F-02


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP/1.1 to `Host: localhost` over the launcher's Unix socket; outbound only."""

    def __init__(self, socket_path: str, timeout_s: float) -> None:
        super().__init__("localhost", timeout=timeout_s)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
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
        nonce = launcher_nonce(identity_nonce)
        body = json.dumps({"audience": audience, "nonces": [nonce], "token_type": token_type})
        connection = _UnixHTTPConnection(self._socket_path, self._timeout_s)
        try:
            connection.request(
                "POST", _TOKEN_PATH, body=body, headers={"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            raw = response.read(self._max_response_bytes + 1)
        finally:
            connection.close()
        return parse_token_metadata(
            raw.decode("utf-8"),
            audience=audience,
            expected_nonce=nonce,
            max_token_bytes=self._max_response_bytes,
        )
