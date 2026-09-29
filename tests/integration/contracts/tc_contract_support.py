"""Shared helpers for the INC-1 contract tests (Tech Lead, Wave 0).

The contract tests exercise only the public API frozen in docs/tasks/INC-1/API.md. They are
expected to fail until the implementing tasks named in docs/tasks/INC-1/WAVES.md merge.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
from dataclasses import dataclass
from pathlib import Path

from teecustody_sim import LaunchConfig, Simulator, SimulatorConfig

AUDIENCE = "https://contract.teecustody.test/tee"
IMAGE_REFERENCE = "localhost/teecustody-contract:1"
IMAGE_DIGEST = "sha256:" + "ab" * 32
ARGS = ("/app/workload",)
ENV = (("PYTHONUNBUFFERED", "1"),)


@dataclass(frozen=True)
class RunningSimulator:
    simulator: Simulator
    config: SimulatorConfig


def jws_payload(token: str) -> dict[str, object]:
    """Decode the (unverified) payload of a compact JWS."""
    segment = token.split(".")[1]
    decoded = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    assert isinstance(decoded, dict)
    return decoded


def jws_header(token: str) -> dict[str, object]:
    segment = token.split(".")[0]
    decoded = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    assert isinstance(decoded, dict)
    return decoded


def simulator_config(root: Path, **overrides: object) -> SimulatorConfig:
    launcher_dir = root / "launcher"
    launcher_dir.mkdir(exist_ok=True)
    values: dict[str, object] = {
        "state_dir": root / "state",
        "socket_path": launcher_dir / "teeserver.sock",
        "token_file_path": launcher_dir / "attestation_verifier_claims_token",
        "launch": LaunchConfig(
            image_reference=IMAGE_REFERENCE,
            image_digest=IMAGE_DIGEST,
            args=ARGS,
            env=ENV,
        ),
        "audience": AUDIENCE,
        "issuer_port": 0,
    }
    values.update(overrides)
    return SimulatorConfig(**values)  # type: ignore[arg-type]


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path) -> None:
        super().__init__("localhost", timeout=5.0)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(str(self._socket_path))
        self.sock = sock


def post_launcher(socket_path: Path, body: bytes) -> tuple[int, bytes]:
    """POST raw bytes to the launcher token endpoint (FACTS F-02) and return (status, body)."""
    connection = _UnixHTTPConnection(socket_path)
    try:
        connection.request(
            "POST", "/v1/token", body=body, headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()
