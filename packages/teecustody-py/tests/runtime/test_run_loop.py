"""T-29: `RunLoop` (INC-2-API §4.13; spec §5.1, §11; FR-1, FR-5, SR-12, SR-14, NFR-3).

`ChannelServer` (T-28, same wave) is replaced by `FakeServer` through `monkeypatch` (WAVES R-8).
"""

import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any, ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from teecustody.attest.lifecycle import RefreshOutcome
from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.audit.ports import AppendResult, AuditClass, AuditKey, AuditRecord
from teecustody.channel.codec import decode_bundle, prekey_signing_message
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
from teecustody.runtime import RunLoop, StopCode, WorkloadStopped, run_loop
from teecustody.wire import CanonicalValue, DecodeLimits

AUDIENCE = "https://runloop.teecustody.test/tee"
DIGEST = "sha256:" + "ab" * 32
OTHER_DIGEST = "sha256:" + "cd" * 32
START = 1_800_000_000.25
TOKEN_LIFETIME = 3600
BUNDLE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)
PARAMS = ChannelParams(prekey_batch=4, prekey_low_water=1, prekey_ttl_s=600)
CLIENT = "c1" * 16


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def token_value(digest: str, nonce: bytes) -> str:
    header = b64(json.dumps({"alg": "RS256"}).encode())
    payload = b64(
        json.dumps(
            {"eat_nonce": nonce.hex(), "submods": {"container": {"image_digest": digest}}}
        ).encode()
    )
    return f"{header}.{payload}.{b64(b'not-checked')}"


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeLauncher:
    """Issues JWS-shaped tokens carrying `digest`; fails while `fail` is set; records every call."""

    def __init__(self, clock: FakeClock, lifetime: int = TOKEN_LIFETIME) -> None:
        self.clock = clock
        self.lifetime = lifetime
        self.digest = DIGEST
        self.fail = False
        self.calls: list[tuple[str, str, bytes]] = []
        self.issued: list[AttestationToken] = []

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        self.calls.append((audience, token_type, identity_nonce))
        if self.fail:
            raise LauncherError(LauncherErrorCode.UNAVAILABLE)
        now = int(self.clock())
        token = AttestationToken(
            value=token_value(self.digest, identity_nonce),
            issued_at=now,
            expires_at=now + self.lifetime,
        )
        self.issued.append(token)
        return token


class FakeQueue:
    """WorkloadQueue that records every call in order and serves scripted pulls."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.bundles: list[tuple[str, bytes, int]] = []
        self.inbox: list[QueueMessage] = []
        self.pull_errors: list[Exception] = []
        self.publish_errors: list[Exception] = []

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        self.calls.append(("publish_bundle", instance_id))
        self.bundles.append((instance_id, bundle, expires_at))

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        self.calls.append(("pull", instance_id, max_messages, wait_s))
        if self.pull_errors:
            raise self.pull_errors.pop(0)
        out, self.inbox = self.inbox[:max_messages], self.inbox[max_messages:]
        return out

    def ack(self, message_id: str) -> None:
        self.calls.append(("ack", message_id))

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        self.calls.append(("publish_response", client_id, request_id, body))
        if self.publish_errors:
            raise self.publish_errors.pop(0)

    def withdraw_bundle(self, instance_id: str) -> None:
        self.calls.append(("withdraw_bundle", instance_id))

    def named(self, name: str) -> list[tuple[Any, ...]]:
        return [c for c in self.calls if c[0] == name]


class RecordingSink:
    def __init__(self) -> None:
        self.records: list[tuple[AuditKey, AuditRecord]] = []

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        self.records.append((key, record))
        return AppendResult.CREATED

    def of(self, record_class: AuditClass) -> list[AuditRecord]:
        return [r for k, r in self.records if k.record_class is record_class]


class RecordingLogger:
    def __init__(self) -> None:
        self.lines: list[tuple[str, str, dict[str, object]]] = []

    def info(self, outcome: str, **fields: object) -> None:
        self.lines.append(("info", outcome, fields))

    def warning(self, outcome: str, **fields: object) -> None:
        self.lines.append(("warning", outcome, fields))

    def error(self, outcome: str, **fields: object) -> None:
        self.lines.append(("error", outcome, fields))

    def outcomes(self) -> list[str]:
        return [outcome for _, outcome, _ in self.lines]


class RecordingOpener:
    def __init__(self) -> None:
        self.closed_calls: list[tuple[SessionInfo, CloseReason]] = []
        self.raise_on_close = False

    def open(self, request: OpenRequest) -> OpenResult:
        return OpenRejected(RemoteErrorCode.NOT_AUTHORIZED)

    def closed(self, session: SessionInfo, reason: CloseReason) -> None:
        self.closed_calls.append((session, reason))
        if self.raise_on_close:
            raise RuntimeError("opener failure")


class NullHandler:
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody:
        return HandlerError(RemoteErrorCode.UNKNOWN_OPERATION)


class FakeServer:
    """Stands in for `ChannelServer`; `script` maps a body to its result (default: no response)."""

    instances: ClassVar[list["FakeServer"]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.bodies: list[bytes] = []
        self.script: dict[bytes, ProcessResult] = {}
        self.on_process: Callable[[bytes], None] | None = None
        FakeServer.instances.append(self)

    def process(self, body: bytes) -> ProcessResult:
        self.bodies.append(body)
        if self.on_process is not None:
            self.on_process(body)
        return self.script.get(body, ProcessResult("REQUEST_INVALID", None))


class World:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        params: ChannelParams = PARAMS,
        limits: BoundaryLimits | None = None,
        start: bool = True,
    ) -> None:
        FakeServer.instances = []
        monkeypatch.setattr(run_loop, "ChannelServer", FakeServer)
        self.clock = FakeClock()
        self.launcher = FakeLauncher(self.clock)
        self.queue = FakeQueue()
        self.sink = RecordingSink()
        self.logger = RecordingLogger()
        self.opener = RecordingOpener()
        self.params = params
        self.limits = limits if limits is not None else BoundaryLimits(pull_wait_s=0.01)
        self.loop = RunLoop(
            launcher=self.launcher,
            queue=self.queue,
            audit_sink=self.sink,
            opener=self.opener,
            handler=NullHandler(),
            audience=AUDIENCE,
            token_type="OIDC",
            params=params,
            limits=self.limits,
            clock=self.clock,
            logger=self.logger,
        )
        if start:
            self.loop.start()

    @property
    def server(self) -> FakeServer:
        return FakeServer.instances[-1]


def published_bundle(world: World, index: int = -1) -> Any:
    instance_id, body, _ = world.queue.bundles[index]
    assert instance_id == world.loop.instance_id
    return decode_bundle(body, BUNDLE_LIMITS)


# ---------------------------------------------------------------- criterion 1: start()
def test_c1_start_attests_the_identity_key_and_publishes_one_signed_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)

    [(audience, token_type, nonce)] = world.launcher.calls
    [(instance_id, _, expires_at)] = world.queue.bundles
    bundle = published_bundle(world)
    assert (audience, token_type) == (AUDIENCE, "OIDC")
    assert nonce == hashlib.sha256(bundle.ik_pub).digest()
    assert instance_id == bundle.instance_id == world.loop.instance_id
    assert bundle.token == world.launcher.issued[0].value
    assert len(bundle.prekeys) == PARAMS.prekey_batch
    ik = Ed25519PublicKey.from_public_bytes(bundle.ik_pub)
    for entry in bundle.prekeys:
        message = prekey_signing_message(
            bundle.instance_id, entry.id, entry.pub, entry.not_after, DIGEST
        )
        ik.verify(entry.sig, message)
    token_exp = world.launcher.issued[0].expires_at
    assert expires_at == min(token_exp, max(e.not_after for e in bundle.prekeys))
    assert world.logger.outcomes().count("BUNDLE_PUBLISHED") == 1


# ---------------------------------------------------------------- criterion 3: expired token
def test_c3_an_expired_token_shuts_down_then_stops_with_attestation_expired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.launcher.fail = True
    world.clock.now += TOKEN_LIFETIME + 1

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.ATTESTATION_EXPIRED
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]


# ---------------------------------------------------------------- criterion 4: digest change
def test_c4_a_refreshed_token_with_another_digest_shuts_down_then_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.launcher.digest = OTHER_DIGEST
    world.clock.now += TOKEN_LIFETIME - PARAMS.refresh_margin_s

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.DIGEST_CHANGED
    assert len(world.launcher.issued) == 2
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]
    assert len(world.queue.bundles) == 1  # the other digest is never published


def test_c4_a_refreshed_token_with_the_same_digest_keeps_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.clock.now += TOKEN_LIFETIME - PARAMS.refresh_margin_s

    assert world.loop.tick().refresh is RefreshOutcome.REFRESHED
    assert world.queue.named("withdraw_bundle") == []
