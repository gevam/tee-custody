"""T-29 criterion 9 (NFR-2): the run loop never binds or listens on a socket.

Runs against the simulator launcher (outbound AF_UNIX only). `ChannelServer` (T-28, same wave) is
replaced by a stub through `monkeypatch` (WAVES R-8).
"""

import shutil
import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from teecustody.attest import ConfidentialSpaceLauncher
from teecustody.audit.ports import AppendResult, AuditKey, AuditRecord
from teecustody.channel.ports import (
    CloseReason,
    FrameResultBody,
    HandlerError,
    OpenRejected,
    OpenRequest,
    OpenResult,
    RemoteErrorCode,
    SessionInfo,
)
from teecustody.channel.server import ProcessResult
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.queue.ports import QueueMessage
from teecustody.runtime import RunLoop, run_loop
from teecustody.wire import CanonicalValue
from teecustody_sim import LaunchConfig, Simulator, SimulatorConfig

AUDIENCE = "https://no-listener.teecustody.test/tee"


class InMemoryWorkloadQueue:
    def __init__(self) -> None:
        self.bundles: dict[str, bytes] = {}
        self.inbox = [
            QueueMessage(message_id="1" * 32, request_id="2" * 32, body=b"x", published_at=0.0)
        ]

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        self.bundles[instance_id] = bundle

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        out, self.inbox = self.inbox[:max_messages], self.inbox[max_messages:]
        return out

    def ack(self, message_id: str) -> None:
        del message_id

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        del client_id, request_id, body

    def withdraw_bundle(self, instance_id: str) -> None:
        self.bundles.pop(instance_id, None)


class Sink:
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        return AppendResult.CREATED


class Opener:
    def open(self, request: OpenRequest) -> OpenResult:
        return OpenRejected(RemoteErrorCode.NOT_AUTHORIZED)

    def closed(self, session: SessionInfo, reason: CloseReason) -> None:
        del session, reason


class Handler:
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody:
        return HandlerError(RemoteErrorCode.UNKNOWN_OPERATION)


class Server:
    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    def process(self, body: bytes) -> ProcessResult:
        return ProcessResult("REQUEST_INVALID", None)


@pytest.fixture
def launcher_socket() -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix="tc", dir="/tmp"))  # AF_UNIX paths are short
    try:
        (root / "launcher").mkdir()
        config = SimulatorConfig(
            state_dir=root / "state",
            socket_path=root / "launcher" / "teeserver.sock",
            token_file_path=root / "launcher" / "attestation_verifier_claims_token",
            launch=LaunchConfig(
                image_reference="localhost/teecustody-runloop:1",
                image_digest="sha256:" + "ab" * 32,
                args=("/app/workload",),
                env=(),
            ),
            audience=AUDIENCE,
            issuer_port=0,
        )
        with Simulator(config, environ={}):
            yield config.socket_path
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_c9_start_and_ticks_never_bind_or_listen(
    launcher_socket: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny(*_args: object, **_kwargs: object) -> None:
        pytest.fail("the workload must not bind or listen (NFR-2)")

    monkeypatch.setattr(socket.socket, "bind", deny)
    monkeypatch.setattr(socket.socket, "listen", deny)
    monkeypatch.setattr(run_loop, "ChannelServer", Server)
    queue = InMemoryWorkloadQueue()
    loop = RunLoop(
        launcher=ConfidentialSpaceLauncher(
            str(launcher_socket), timeout_s=5.0, max_response_bytes=65536
        ),
        queue=queue,
        audit_sink=Sink(),
        opener=Opener(),
        handler=Handler(),
        audience=AUDIENCE,
        token_type="OIDC",
        params=ChannelParams(prekey_batch=4, prekey_low_water=1),
        limits=BoundaryLimits(pull_wait_s=0.01),
    )

    loop.start()
    reports = [loop.tick() for _ in range(5)]
    loop.shutdown()

    assert sum(r.processed for r in reports) == 1
    assert queue.bundles == {}
