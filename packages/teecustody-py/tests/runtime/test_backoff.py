"""T-29: attestation-refresh and pull backoff (B-08, SR-4; INC-2-API §4.13).

`ChannelServer` (T-28, same wave) is replaced by a stub through `monkeypatch` (WAVES R-8).
"""

import base64
import json
from typing import Any

import pytest

from teecustody.attest.lifecycle import RefreshOutcome
from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode
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
from teecustody.queue.ports import QueueError, QueueErrorCode, QueueMessage
from teecustody.runtime import RunLoop, StopCode, WorkloadStopped, run_loop
from teecustody.wire import CanonicalValue

RETRY_MIN, RETRY_MAX = 30, 300
START = 1_800_000_000.5
DIGEST = "sha256:" + "ab" * 32


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> float:
        return self.now


class Launcher:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.fail = False
        self.calls = 0
        self.lifetime = 3600

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        self.calls += 1
        if self.fail:
            raise LauncherError(LauncherErrorCode.UNAVAILABLE)
        claims = {"submods": {"container": {"image_digest": DIGEST}}}
        value = f"{_b64(b'{}')}.{_b64(json.dumps(claims).encode())}.{_b64(b'sig')}"
        now = int(self.clock())
        return AttestationToken(value=value, issued_at=now, expires_at=now + self.lifetime)


class Queue:
    def __init__(self) -> None:
        self.pulls = 0
        self.pull_errors: list[Exception] = []
        self.withdrawn = 0

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        del instance_id, bundle, expires_at

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        self.pulls += 1
        if self.pull_errors:
            raise self.pull_errors.pop(0)
        return []

    def ack(self, message_id: str) -> None:
        del message_id

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        del client_id, request_id, body

    def withdraw_bundle(self, instance_id: str) -> None:
        del instance_id
        self.withdrawn += 1


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


class World:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        refresh_margin_s: int = 3599,
        lifetime: int = 3600,
        retry_max: int = RETRY_MAX,
    ) -> None:
        self.retry_max = retry_max
        monkeypatch.setattr(run_loop, "ChannelServer", Server)
        self.clock = Clock()
        self.launcher = Launcher(self.clock)
        self.launcher.lifetime = lifetime
        self.queue = Queue()
        # By default a margin of 3599 s makes the 3600 s token due one second after issue.
        self.loop = RunLoop(
            launcher=self.launcher,
            queue=self.queue,
            audit_sink=Sink(),
            opener=Opener(),
            handler=Handler(),
            audience="https://backoff.teecustody.test/tee",
            token_type="OIDC",
            params=ChannelParams(
                prekey_batch=2, prekey_low_water=1, refresh_margin_s=refresh_margin_s
            ),
            limits=BoundaryLimits(
                pull_wait_s=0.01,
                attestation_retry_min_s=RETRY_MIN,
                attestation_retry_max_s=retry_max,
            ),
            clock=self.clock,
        )
        self.loop.start()

    def tick(self, n: int) -> None:
        for _ in range(n):
            self.loop.tick()


# ---------------------------------------------------------------- criterion 2: B-08
def test_c2_a_thousand_ticks_with_a_failing_launcher_make_exactly_one_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.clock.now += 2
    world.launcher.fail = True

    world.tick(1000)

    assert world.launcher.calls == 2  # start() and the one failed refresh


def test_c2_failures_wait_min_then_double_up_to_max_and_success_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.clock.now += 2
    world.launcher.fail = True
    assert world.loop.tick().refresh is RefreshOutcome.FAILED_KEPT_CURRENT
    calls = world.launcher.calls
    for delay in (30, 60, 120, 240, 300, 300):
        world.clock.now += delay - 1
        world.tick(20)
        assert world.launcher.calls == calls, delay
        assert world.loop.tick().refresh is None
        world.clock.now += 1
        world.tick(20)
        calls += 1
        assert world.launcher.calls == calls, delay

    world.launcher.fail = False
    world.clock.now += RETRY_MAX
    assert world.loop.tick().refresh is RefreshOutcome.REFRESHED

    world.clock.now += 2
    world.launcher.fail = True
    world.loop.tick()
    calls = world.launcher.calls
    world.clock.now += RETRY_MIN - 1
    world.tick(20)
    assert world.launcher.calls == calls
    world.clock.now += 1
    world.tick(20)
    assert world.launcher.calls == calls + 1


def test_c2_a_refresh_that_is_not_due_calls_no_launcher(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)

    report = world.loop.tick()

    assert report.refresh is RefreshOutcome.NOT_DUE
    assert world.launcher.calls == 1


# ---------------------------------------------------------------- criterion 6: pull backoff
def unavailable(n: int) -> list[Exception]:
    return [QueueError(QueueErrorCode.UNAVAILABLE) for _ in range(n)]


def pull_until_failures_exhausted(world: World, expected_pulls: int) -> None:
    """Tick through the pull backoff after one failed pull: never early, once at each delay."""
    base = world.queue.pulls - 1
    for failures in range(1, expected_pulls):
        assert world.queue.pulls == base + failures
        delay = min(world.retry_max, RETRY_MIN * 2 ** (failures - 1))
        world.clock.now += delay - 1
        world.tick(20)
        assert world.queue.pulls == base + failures, failures
        world.clock.now += 1
        world.loop.tick()


def quiet_world(monkeypatch: pytest.MonkeyPatch) -> World:
    """No refresh or pre-key expiry (each a republish, a queue success) during the streaks."""
    return World(monkeypatch, refresh_margin_s=300, lifetime=86_400, retry_max=60)


def test_c6_ten_consecutive_unavailable_pulls_shut_down_and_stop(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    world = quiet_world(monkeypatch)
    world.queue.pull_errors = unavailable(10)
    world.loop.tick()

    with pytest.raises(WorkloadStopped) as stopped:
        pull_until_failures_exhausted(world, 10)

    assert stopped.value.code is StopCode.QUEUE_UNAVAILABLE
    assert world.queue.pulls == 10
    assert world.queue.withdrawn == 1
    pull_logs = [r for r in caplog.records if r.getMessage() == "QUEUE_PULL_FAILED"]
    assert len(pull_logs) == 10


def test_c6_fewer_than_ten_failures_recover_and_reset_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = quiet_world(monkeypatch)
    world.queue.pull_errors = unavailable(9)
    world.loop.tick()
    pull_until_failures_exhausted(world, 10)  # the 10th pull succeeds
    assert world.queue.pulls == 10

    world.queue.pull_errors = unavailable(9)
    world.loop.tick()
    pull_until_failures_exhausted(world, 10)

    assert world.queue.pulls == 20
    assert world.queue.withdrawn == 0


def test_c6_pull_backoff_does_not_delay_the_attestation_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.queue.pull_errors = unavailable(1)
    world.loop.tick()
    world.clock.now += 2  # refresh due; pull still backing off

    report = world.loop.tick()

    assert report.refresh is RefreshOutcome.REFRESHED
    assert world.queue.pulls == 1
