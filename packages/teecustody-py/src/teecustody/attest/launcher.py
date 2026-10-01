"""Confidential Space launcher socket client."""

from typing import Final

from teecustody.attest.ports import AttestationToken

DEFAULT_LAUNCHER_SOCKET: Final = "/run/container_launcher/teeserver.sock"


class ConfidentialSpaceLauncher:
    def __init__(
        self,
        socket_path: str = DEFAULT_LAUNCHER_SOCKET,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> None:
        raise NotImplementedError("T-06")

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        raise NotImplementedError("T-06")
