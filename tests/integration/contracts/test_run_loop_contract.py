"""Contract: workload RunLoop against the simulator launcher (FR-1, FR-5, NFR-2, SR-4 B-08;
INC-2-API §4.13; spec §5.1).

Expected red until T-07..T-13, T-22..T-24, T-28 and T-29 merge (docs/tasks/INC-2/WAVES.md).
"""

from __future__ import annotations

import hashlib
import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tc_channel_support import FakeClock, fake_token
from tc_contract_support import AUDIENCE, IMAGE_DIGEST, RunningSimulator, jws_payload

from teecustody.attest import AttestationToken, ConfidentialSpaceLauncher, LauncherError
from teecustody.attest import LauncherErrorCode as Code
from teecustody.channel.codec import decode_bundle, prekey_signing_message
from teecustody.config import BoundaryLimits
from teecustody.queue import QueueMessage
from teecustody.runtime import RunLoop
from teecustody.wire import DecodeLimits
from teecustody_sim.backends import InMemoryAuditSink, InMemoryQueue
from tests.support.channel_doubles import EchoHandler, StaticShareOpener

BUNDLE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)


def test_start_publishes_an_attested_signed_bundle(
    running_simulator: RunningSimulator, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_listen(*args: object) -> None:
        raise AssertionError("the workload must not listen (NFR-2)")

    monkeypatch.setattr(socket.socket, "listen", no_listen)
    queue = InMemoryQueue()
    loop = RunLoop(
        launcher=ConfidentialSpaceLauncher(
            str(running_simulator.config.socket_path), timeout_s=5.0, max_response_bytes=65536
        ),
        queue=queue,
        audit_sink=InMemoryAuditSink(),
        opener=StaticShareOpener({}),
        handler=EchoHandler(),
        audience=AUDIENCE,
        token_type="OIDC",
        limits=BoundaryLimits(pull_wait_s=0.01),
    )
    try:
        loop.start()
        loop.tick()
        [published] = queue.list_bundles(16)
    finally:
        loop.shutdown()

    assert published.instance_id == loop.instance_id
    bundle = decode_bundle(published.bundle, BUNDLE_LIMITS)
    assert bundle.instance_id == loop.instance_id
    claims = jws_payload(bundle.token)
    assert claims["eat_nonce"] == hashlib.sha256(bundle.ik_pub).hexdigest()
    ik = Ed25519PublicKey.from_public_bytes(bundle.ik_pub)
    for entry in bundle.prekeys:
        message = prekey_signing_message(
            bundle.instance_id, entry.id, entry.pub, entry.not_after, IMAGE_DIGEST
        )
        ik.verify(entry.sig, message)
    assert queue.list_bundles(16) == []


class _FailingAfterFirstLauncher:
    def __init__(self, clock: FakeClock) -> None:
        self.calls = 0
        self._clock = clock

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        self.calls += 1
        if self.calls > 1:
            raise LauncherError(Code.UNAVAILABLE)
        now = int(self._clock())
        return AttestationToken(
            value=fake_token(nonce_hex=identity_nonce.hex()), issued_at=now, expires_at=now + 400
        )


class _EmptyQueue:
    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        del instance_id, bundle, expires_at

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        del instance_id, max_messages, wait_s
        return []

    def ack(self, message_id: str) -> None:
        del message_id

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        del client_id, request_id, body

    def withdraw_bundle(self, instance_id: str) -> None:
        del instance_id


def test_failed_refresh_is_retried_no_sooner_than_the_minimum_interval() -> None:
    clock = FakeClock()
    launcher = _FailingAfterFirstLauncher(clock)
    limits = BoundaryLimits(attestation_retry_min_s=30, attestation_retry_max_s=300)
    loop = RunLoop(
        launcher=launcher,
        queue=_EmptyQueue(),
        audit_sink=InMemoryAuditSink(),
        opener=StaticShareOpener({}),
        handler=EchoHandler(),
        audience=AUDIENCE,
        token_type="OIDC",
        limits=limits,
        clock=clock,
    )
    loop.start()
    clock.now += 100  # inside the refresh margin, token still valid

    for _ in range(1000):
        loop.tick()
    assert launcher.calls == 2

    clock.now += 29
    loop.tick()
    assert launcher.calls == 2
    clock.now += 1
    loop.tick()
    assert launcher.calls == 3
    loop.shutdown()
