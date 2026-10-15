"""T-29: `RunLoop` (INC-2-API §4.13; spec §5.1, §11; FR-1, FR-5, SR-12, SR-14, NFR-3).

`ChannelServer` (T-28, same wave) is replaced by `FakeServer` through `monkeypatch` (WAVES R-8).
"""

import base64
import hashlib
import json
import threading
from collections.abc import Callable
from typing import Any, ClassVar

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from teecustody.attest.lifecycle import RefreshOutcome
from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode
from teecustody.audit.emitter import AggregateOutcome
from teecustody.audit.ports import AppendResult, AuditClass, AuditKey, AuditRecord
from teecustody.channel import hpke
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
from teecustody.channel.server import OutboundResponse, ProcessResult
from teecustody.channel.session import SessionTable, T2cSealer
from teecustody.config import BoundaryLimits, ChannelParams, ConfigError, ConfigErrorCode
from teecustody.queue.ports import QueueError, QueueErrorCode, QueueMessage
from teecustody.runtime import RunLoop, StopCode, WorkloadStopped, run_loop
from teecustody.secrets import Secret
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


def token_value(digest: str, nonce: bytes, iat: int) -> str:
    header = b64(json.dumps({"alg": "RS256"}).encode())
    claims = {
        "iat": iat,
        "eat_nonce": nonce.hex(),
        "submods": {"container": {"image_digest": digest}},
    }
    payload = b64(json.dumps(claims).encode())
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
            value=token_value(self.digest, identity_nonce, now),
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
        self.bundle_errors: list[Exception] = []
        self.ack_errors: list[Exception] = []

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        self.calls.append(("publish_bundle", instance_id))
        if self.bundle_errors:
            raise self.bundle_errors.pop(0)
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
        if self.ack_errors:
            raise self.ack_errors.pop(0)

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


# ---------------------------------------------------------------- criterion 5: process and respond
def message(n: int, body: bytes) -> QueueMessage:
    return QueueMessage(
        message_id=f"{n:032x}", request_id=f"{n + 100:032x}", body=body, published_at=START
    )


def answered(world: World, n: int, body: bytes) -> bytes:
    """Queue message n; the fake server answers it with a fresh response body object."""
    response = bytes(f"sealed-{n}", "ascii")
    world.server.script[body] = ProcessResult("FRAME_ACCEPTED", OutboundResponse(CLIENT, response))
    world.queue.inbox.append(message(n, body))
    return response


def test_c5_each_pulled_message_is_processed_answered_to_its_route_and_acked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    first = answered(world, 1, b"req-1")
    world.queue.inbox.append(message(2, b"garbage"))  # no response
    world.queue.calls.clear()

    report = world.loop.tick()

    assert report.processed == 2
    assert world.server.bodies == [b"req-1", b"garbage"]
    pull = (
        "pull",
        world.loop.instance_id,
        world.limits.pull_max_messages,
        world.limits.pull_wait_s,
    )
    assert [c for c in world.queue.calls if c[0] != "publish_bundle"] == [
        pull,
        ("publish_response", CLIENT, f"{101:032x}", first),
        ("ack", f"{1:032x}"),
        ("ack", f"{2:032x}"),
    ]


def test_c5_a_failed_publish_is_retried_once_with_the_identical_bytes_object_then_acked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    body = answered(world, 1, b"req-1")
    world.queue.publish_errors = [QueueError(QueueErrorCode.UNAVAILABLE)]

    world.loop.tick()

    attempts = world.queue.named("publish_response")
    assert len(attempts) == 2
    assert attempts[0][3] is body
    assert attempts[1][3] is body
    assert world.queue.calls[-1] == ("ack", f"{1:032x}")
    assert world.server.bodies == [b"req-1"]  # never processed (or sealed) again


def test_c5_publish_failing_twice_is_logged_and_the_message_still_acked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    answered(world, 1, b"req-1")
    world.queue.publish_errors = [
        QueueError(QueueErrorCode.UNAVAILABLE),
        QueueError(QueueErrorCode.UNAVAILABLE),
    ]

    world.loop.tick()

    assert len(world.queue.named("publish_response")) == 2
    assert world.queue.calls[-1] == ("ack", f"{1:032x}")
    failures = [line for line in world.logger.lines if line[1] == "RESPONSE_PUBLISH_FAILED"]
    assert failures
    assert all(fields == {} for _, _, fields in failures)


# ---------------------------------------------------------------- criterion 7: PREKEY_BURN_HIGH
BURN_LIMITS = BoundaryLimits(pull_wait_s=0.01, prekey_burn_alert_threshold=2)
BURN_PARAMS = ChannelParams(prekey_batch=20, prekey_low_water=1, prekey_ttl_s=3600)


def burn(world: World, count: int) -> None:
    """One tick in which `count` opens each consume a pre-key."""
    prekeys = world.server.kwargs["prekeys"]
    world.server.on_process = lambda body: prekeys.take(int(body))
    world.queue.inbox.extend(
        message(i, str(e.id).encode()) for i, e in enumerate(prekeys.public_entries()[:count])
    )
    world.loop.tick()
    world.server.on_process = None


def burn_alerts(world: World) -> list[AuditRecord]:
    return [r for r in world.sink.of(AuditClass.ALERT) if r.outcome == "PREKEY_BURN_HIGH"]


def test_c7_consumption_above_the_threshold_raises_exactly_one_alert_for_that_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS, limits=BURN_LIMITS)
    world.clock.now += 1
    burn(world, 3)
    assert burn_alerts(world) == []  # checked at interval end only

    world.clock.now = START + 60
    for _ in range(5):
        world.loop.tick()

    [alert] = burn_alerts(world)
    assert (alert.interval_start, alert.interval_end) == (
        int(START * 1000),
        int(START * 1000) + 60_000,
    )
    assert alert.count is None


def test_c7_consumption_at_the_threshold_raises_no_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch, params=BURN_PARAMS, limits=BURN_LIMITS)
    world.clock.now += 1
    burn(world, 2)

    world.clock.now += 120
    world.loop.tick()

    assert burn_alerts(world) == []


def test_c7_consumption_is_counted_per_interval_not_across_the_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS, limits=BURN_LIMITS)
    world.clock.now = START + 59
    burn(world, 2)
    world.clock.now = START + 61  # the first interval ends before this tick consumes
    burn(world, 2)
    world.clock.now = START + 125
    burn(world, 3)  # third interval [START+120, START+180)

    world.clock.now = START + 1000
    world.loop.tick()

    [alert] = burn_alerts(world)
    start_ms = int((START + 120) * 1000)
    assert (alert.interval_start, alert.interval_end) == (start_ms, start_ms + 60_000)


# ---------------------------------------------------------------- criterion 8: republish
def test_c8_a_changed_prekey_set_is_republished_at_most_once_per_min_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS)
    interval = world.limits.bundle_republish_min_interval_s
    world.clock.now += 1
    burn(world, 1)  # consumed during step (4): republished on a later tick
    assert len(world.queue.bundles) == 1

    world.clock.now = START + interval - 0.5
    assert world.loop.tick().bundle_published is False
    world.clock.now = START + interval
    assert world.loop.tick().bundle_published is True
    burn(world, 1)
    for _ in range(3):
        world.clock.now += 1
        world.loop.tick()
    assert len(world.queue.bundles) == 2
    world.clock.now = START + 2 * interval
    world.loop.tick()

    assert len(world.queue.bundles) == 3
    live_ids = [e.id for e in world.server.kwargs["prekeys"].public_entries()]
    assert [e.id for e in published_bundle(world).prekeys] == live_ids
    assert world.logger.outcomes().count("BUNDLE_PUBLISHED") == 3


def test_c8_an_unchanged_bundle_is_not_republished(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.clock.now += 60

    report = world.loop.tick()

    assert report.bundle_published is False
    assert len(world.queue.bundles) == 1


def test_c8_expired_prekeys_are_replaced_with_new_ids_and_republished(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    first_ids = [e.id for e in published_bundle(world).prekeys]
    world.clock.now += PARAMS.prekey_ttl_s

    assert world.loop.tick().bundle_published is True

    bundle = published_bundle(world)
    assert len(bundle.prekeys) == PARAMS.prekey_batch
    assert min(e.id for e in bundle.prekeys) > max(first_ids)
    assert world.queue.bundles[-1][2] == min(
        world.launcher.issued[-1].expires_at, max(e.not_after for e in bundle.prekeys)
    )


def test_c8_a_refreshed_token_is_republished_under_the_same_identity_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(
        monkeypatch, params=ChannelParams(prekey_batch=4, prekey_low_water=1, refresh_margin_s=3599)
    )
    before = published_bundle(world)
    world.clock.now += world.limits.bundle_republish_min_interval_s

    report = world.loop.tick()

    after = published_bundle(world)
    assert report.refresh is RefreshOutcome.REFRESHED
    assert report.bundle_published is True
    assert after.token == world.launcher.issued[-1].value != before.token
    assert (after.ik_pub, after.prekeys) == (before.ik_pub, before.prekeys)


def test_c8_a_refresh_inside_the_min_interval_is_published_once_it_has_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(
        monkeypatch, params=ChannelParams(prekey_batch=4, prekey_low_water=1, refresh_margin_s=3599)
    )
    world.clock.now += world.limits.bundle_republish_min_interval_s
    assert world.loop.tick().bundle_published is True  # refreshed and published
    world.clock.now += 2
    assert world.loop.tick().refresh is RefreshOutcome.REFRESHED
    assert len(world.queue.bundles) == 2
    world.launcher.fail = True  # no further refresh: only the pending one remains

    world.clock.now += world.limits.bundle_republish_min_interval_s
    world.loop.tick()

    assert len(world.queue.bundles) == 3
    assert published_bundle(world).token == world.launcher.issued[-1].value


# ---------------------------------------------------------------- criterion 10: shutdown
SESSION_ID = bytes(range(16))


def open_session(world: World, session_id: bytes = SESSION_ID, client_id: str = CLIENT) -> Secret:
    sk_c2t = Secret.random(32)
    world.server.kwargs["sessions"].create(
        session_id=session_id, client_id=client_id, sk_c2t=sk_c2t, t2c=T2cSealer(Secret.random(32))
    )
    return sk_c2t


def test_c10_shutdown_withdraws_closes_destroys_and_flushes_once_even_when_called_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    sk_c2t = open_session(world)
    prekeys = world.server.kwargs["prekeys"]
    private = prekeys.take(prekeys.public_entries()[0].id)  # still owned by the test
    world.server.kwargs["audit"].count(AggregateOutcome.REQUEST_INVALID)

    world.loop.shutdown()
    world.loop.shutdown()

    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]
    info = SessionInfo(client_id=CLIENT, session_id=SESSION_ID, instance_id=world.loop.instance_id)
    assert world.opener.closed_calls == [(info, CloseReason.SHUTDOWN)]
    assert sk_c2t.wiped
    closed = [line for line in world.logger.lines if line[1] == "SESSION_CLOSED"]
    assert closed == [
        ("info", "SESSION_CLOSED", {"client_id": CLIENT, "session_id": SESSION_ID.hex()})
    ]
    assert prekeys.public_entries() == ()
    assert not private.wiped
    aggregates = world.sink.of(AuditClass.AGGREGATE)
    assert [(r.outcome, r.count) for r in aggregates] == [("REQUEST_INVALID", 1)]


def test_c10_shutdown_wipes_every_live_prekey(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[Secret] = []
    original = hpke.generate_keypair

    def recording() -> tuple[Secret, bytes]:
        private, public = original()
        captured.append(private)
        return private, public

    monkeypatch.setattr(hpke, "generate_keypair", recording)
    world = World(monkeypatch)

    world.loop.shutdown()

    assert len(captured) == PARAMS.prekey_batch
    assert all(secret.wiped for secret in captured)


def test_c10_an_evicted_session_is_logged_as_evicted_and_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, limits=BoundaryLimits(pull_wait_s=0.01, max_sessions=1))
    open_session(world)
    world.clock.now += world.limits.session_evict_min_idle_s

    open_session(world, session_id=bytes(16), client_id="c2" * 16)

    evicted = SessionInfo(CLIENT, SESSION_ID, world.loop.instance_id)
    assert world.opener.closed_calls == [(evicted, CloseReason.EVICTED)]
    lines = [line for line in world.logger.lines if line[1].startswith("SESSION_")]
    assert lines == [
        ("info", "SESSION_EVICTED", {"client_id": CLIENT, "session_id": SESSION_ID.hex()})
    ]


def test_c10_the_close_callback_itself_swallows_an_opener_failure_after_logging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks: list[Callable[[SessionInfo, CloseReason], None]] = []

    class CapturingTable(SessionTable):
        def __init__(self, **kwargs: Any) -> None:
            callbacks.append(kwargs["on_close"])
            super().__init__(**kwargs)

    monkeypatch.setattr(run_loop, "SessionTable", CapturingTable)
    world = World(monkeypatch)
    world.opener.raise_on_close = True
    info = SessionInfo(CLIENT, SESSION_ID, world.loop.instance_id)

    callbacks[0](info, CloseReason.CLIENT_CLOSE)  # TL-2: does not raise

    assert world.opener.closed_calls == [(info, CloseReason.CLIENT_CLOSE)]
    assert world.logger.outcomes()[-1] == "SESSION_CLOSED"


# ---------------------------------------------------------------- criterion 11: run(stop)
class RecordingStop(threading.Event):
    """A stop event that records every wait; `on_wait` may move the clock or set the event."""

    def __init__(self) -> None:
        super().__init__()
        self.waits: list[float | None] = []
        self.on_wait: Callable[[int], None] = lambda n: None

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout)
        self.on_wait(len(self.waits))
        return self.is_set()


def test_c11_run_ticks_until_stop_and_shuts_down_in_finally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, start=False)
    stop = RecordingStop()
    original_pull = world.queue.pull_requests

    def pull_then_stop(instance_id: str, max_messages: int, wait_s: float) -> list[QueueMessage]:
        if len(world.queue.named("pull")) == 2:
            stop.set()
        return original_pull(instance_id, max_messages, wait_s)

    monkeypatch.setattr(world.queue, "pull_requests", pull_then_stop)

    world.loop.run(stop)

    assert len(world.queue.named("pull")) == 3
    assert len(world.queue.bundles) == 1  # start() ran inside run()
    assert world.queue.calls[-1] == ("withdraw_bundle", world.loop.instance_id)
    assert stop.waits == []  # every tick pulled (the pull itself waits)


def test_c11_a_tick_skipping_its_pull_waits_until_the_pull_is_due_at_most_pull_wait_s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, limits=BoundaryLimits(pull_wait_s=1.0), start=False)
    world.queue.pull_errors = [QueueError(QueueErrorCode.UNAVAILABLE)]
    stop = RecordingStop()

    def on_wait(n: int) -> None:
        if n == 1:
            world.clock.now += world.limits.attestation_retry_min_s - 0.25
        else:
            stop.set()

    stop.on_wait = on_wait

    world.loop.run(stop)

    assert stop.waits == [1.0, pytest.approx(0.25)]
    assert len(world.queue.named("pull")) == 1
    assert len(world.queue.named("withdraw_bundle")) == 1


def test_c11_a_stop_raised_by_a_tick_propagates_after_a_single_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, start=False)
    world.queue.pull_errors = [QueueError(QueueErrorCode.INTERNAL)]

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.run(threading.Event())

    assert stopped.value.code is StopCode.QUEUE_UNAVAILABLE

    assert len(world.queue.named("withdraw_bundle")) == 1


def test_c11_a_failed_start_propagates_and_shutdown_has_nothing_to_undo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, start=False)
    world.launcher.fail = True

    with pytest.raises(LauncherError):
        world.loop.run(threading.Event())

    assert world.queue.calls == []


# ---------------------------------------------------------------- contract decisions
def make_loop(**overrides: Any) -> RunLoop:
    kwargs: dict[str, Any] = {
        "launcher": FakeLauncher(FakeClock()),
        "queue": FakeQueue(),
        "audit_sink": RecordingSink(),
        "opener": RecordingOpener(),
        "handler": NullHandler(),
        "audience": AUDIENCE,
        "token_type": "OIDC",
    }
    kwargs.update(overrides)
    return RunLoop(**kwargs)


def test_evict_min_idle_above_idle_timeout_is_refused_at_construction() -> None:
    with pytest.raises(ConfigError) as err:
        make_loop(
            params=ChannelParams(idle_timeout_s=100),
            limits=BoundaryLimits(session_evict_min_idle_s=101),
        )

    assert err.value.code is ConfigErrorCode.INVALID_LIMITS
    assert err.value.field == "session_evict_min_idle_s"


def test_evict_min_idle_equal_to_idle_timeout_is_accepted() -> None:
    make_loop(
        params=ChannelParams(idle_timeout_s=100),
        limits=BoundaryLimits(session_evict_min_idle_s=100),
    )


def test_instance_id_is_sixteen_random_bytes_in_hex() -> None:
    requested: list[int] = []

    def rng(n: int) -> bytes:
        requested.append(n)
        return bytes(range(n))

    loop = make_loop(rng=rng)

    assert requested == [16]
    assert loop.instance_id == bytes(range(16)).hex()


def test_exhausted_prekey_ids_shut_down_then_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    prekeys = world.server.kwargs["prekeys"]
    world.clock.now += PARAMS.prekey_ttl_s  # every key expires: top_up must generate

    def exhausted() -> int:
        raise RuntimeError("PREKEY_IDS_EXHAUSTED")

    monkeypatch.setattr(prekeys, "top_up", exhausted)

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.PREKEY_IDS_EXHAUSTED
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]


def test_other_prekey_store_errors_are_not_mistaken_for_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)

    def broken() -> int:
        raise RuntimeError("SOMETHING_ELSE")

    monkeypatch.setattr(world.server.kwargs["prekeys"], "top_up", broken)

    with pytest.raises(RuntimeError, match="SOMETHING_ELSE"):
        world.loop.tick()


# ---------------------------------------------------------------- tick order (1)-(7)
def spy(monkeypatch: pytest.MonkeyPatch, order: list[str], target: object, name: str) -> None:
    original = getattr(target, name)

    def recorded(*args: Any, **kwargs: Any) -> Any:
        order.append(name)
        return original(*args, **kwargs)

    monkeypatch.setattr(target, name, recorded)


def test_tick_runs_steps_one_to_seven_in_the_a1_order(monkeypatch: pytest.MonkeyPatch) -> None:
    params = ChannelParams(prekey_batch=4, prekey_low_water=1, refresh_margin_s=3599)
    world = World(monkeypatch, params=params, limits=BURN_LIMITS)
    answered(world, 1, b"req-1")
    world.clock.now += 60  # refresh due, republish due, burn interval ended
    order: list[str] = []
    spy(monkeypatch, order, world.launcher, "get_attestation_token")
    prekeys = world.server.kwargs["prekeys"]
    for name in ("expire", "top_up", "consumed_since"):
        spy(monkeypatch, order, prekeys, name)
    for name in ("publish_bundle", "pull_requests", "publish_response", "ack"):
        spy(monkeypatch, order, world.queue, name)
    spy(monkeypatch, order, world.server, "process")
    spy(monkeypatch, order, world.server.kwargs["sessions"], "expire_idle")
    spy(monkeypatch, order, world.server.kwargs["audit"], "tick")

    world.loop.tick()

    assert order[: order.index("consumed_since")] == [
        "get_attestation_token",
        "expire",
        "top_up",
        "publish_bundle",
        "expire_idle",
        "pull_requests",
        "process",
        "publish_response",
        "ack",
    ]
    assert order[-1] == "tick"
    assert set(order[order.index("consumed_since") : -1]) == {"consumed_since"}


def test_tick_closes_idle_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    sk_c2t = open_session(world)
    world.clock.now += PARAMS.idle_timeout_s

    world.loop.tick()

    assert sk_c2t.wiped
    info = SessionInfo(CLIENT, SESSION_ID, world.loop.instance_id)
    assert world.opener.closed_calls == [(info, CloseReason.IDLE_TIMEOUT)]


def test_tick_writes_audit_aggregates_when_their_interval_ends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.server.kwargs["audit"].count(AggregateOutcome.REQUEST_INVALID)
    world.clock.now += world.limits.audit_aggregate_interval_s

    world.loop.tick()

    assert [(r.outcome, r.count) for r in world.sink.of(AuditClass.AGGREGATE)] == [
        ("REQUEST_INVALID", 1)
    ]


def test_tick_before_start_and_after_shutdown_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch, start=False)
    with pytest.raises(RuntimeError, match="NOT_STARTED"):
        world.loop.tick()
    world.loop.start()
    world.loop.shutdown()

    with pytest.raises(RuntimeError, match="NOT_STARTED"):
        world.loop.tick()
    assert world.queue.named("pull") == []


# ---------------------------------------------------------------- edge cases
def test_a_refreshed_token_without_a_readable_digest_counts_as_a_changed_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.launcher.digest = "sha256:not-a-digest"
    world.clock.now += TOKEN_LIFETIME - PARAMS.refresh_margin_s

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.DIGEST_CHANGED
    assert len(world.queue.named("withdraw_bundle")) == 1


def test_a_failing_withdraw_still_closes_sessions_wipes_keys_and_flushes_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    sk_c2t = open_session(world)
    world.server.kwargs["audit"].count(AggregateOutcome.REQUEST_INVALID)

    def unavailable(instance_id: str) -> None:
        raise QueueError(QueueErrorCode.UNAVAILABLE)

    monkeypatch.setattr(world.queue, "withdraw_bundle", unavailable)

    with pytest.raises(QueueError):
        world.loop.shutdown()
    world.loop.shutdown()  # nothing left to do

    assert sk_c2t.wiped
    assert world.server.kwargs["prekeys"].public_entries() == ()
    assert [r.outcome for r in world.sink.of(AuditClass.AGGREGATE)] == ["REQUEST_INVALID"]


def test_a_stop_code_survives_a_failing_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.launcher.fail = True
    world.clock.now += TOKEN_LIFETIME + 1

    def unavailable(instance_id: str) -> None:
        raise QueueError(QueueErrorCode.UNAVAILABLE)

    monkeypatch.setattr(world.queue, "withdraw_bundle", unavailable)

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.ATTESTATION_EXPIRED


# ---------------------------------------------------------------- criterion 12 (A1): expiry first
def test_c12_failing_refreshes_then_expiry_stop_before_any_processing_at_or_after_exp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)  # refresh_margin 300 s; retry 30 s .. 300 s
    exp = world.launcher.issued[0].expires_at
    world.launcher.fail = True
    attempts: list[float] = []
    processed_at: list[float] = []
    original = world.launcher.get_attestation_token

    def timed(audience: str, token_type: str, nonce: bytes) -> AttestationToken:
        attempts.append(world.clock.now)
        return original(audience, token_type, nonce)

    monkeypatch.setattr(world.launcher, "get_attestation_token", timed)
    bundles_before: list[int] = []

    def tick_every_second_with_a_request() -> None:
        t = float(exp - PARAMS.refresh_margin_s)
        world.server.on_process = lambda _body: processed_at.append(world.clock.now)
        while t < exp + 400:
            world.clock.now = t
            answered(world, int(t) % 10**6, f"req-{t}".encode())
            bundles_before.append(len(world.queue.bundles))
            world.loop.tick()
            t += 1

    with pytest.raises(WorkloadStopped) as stopped:
        tick_every_second_with_a_request()

    assert stopped.value.code is StopCode.ATTESTATION_EXPIRED
    assert world.clock.now == exp
    assert len(world.queue.bundles) == bundles_before[-1]  # no republish at expiry
    assert max(processed_at) < exp
    assert attempts[-1] == exp - 1.0  # the last retry is capped to land before expiry
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]


def test_c12_a_long_backoff_is_capped_one_second_before_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    limits = BoundaryLimits(
        pull_wait_s=0.01, attestation_retry_min_s=300, attestation_retry_max_s=3600
    )
    world = World(monkeypatch, limits=limits)
    exp = world.launcher.issued[0].expires_at
    world.launcher.fail = True
    world.clock.now = exp - 100.0  # due; uncapped next attempt would be exp + 200
    world.loop.tick()
    calls = len(world.launcher.calls)

    world.clock.now = exp - 1.5
    world.loop.tick()
    assert len(world.launcher.calls) == calls
    world.clock.now = exp - 1.0
    world.loop.tick()
    assert len(world.launcher.calls) == calls + 1


def test_c3_expiry_during_the_refresh_call_shuts_down_then_stops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    exp = world.launcher.issued[0].expires_at
    world.clock.now = exp - 0.5
    original = world.launcher.get_attestation_token

    def slow_failure(audience: str, token_type: str, nonce: bytes) -> AttestationToken:
        world.clock.now = exp + 1.0  # the lifecycle sees the token expire during the call
        world.launcher.fail = True
        return original(audience, token_type, nonce)

    monkeypatch.setattr(world.launcher, "get_attestation_token", slow_failure)

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.ATTESTATION_EXPIRED
    assert len(world.queue.named("withdraw_bundle")) == 1


# ---------------------------------------------------------------- criterion 13 (A1): misuse guards
def test_c13_a_second_start_is_refused_and_leaves_live_state_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    sk_c2t = open_session(world)
    prekeys = world.server.kwargs["prekeys"]
    entries = prekeys.public_entries()

    with pytest.raises(RuntimeError, match="ALREADY_STARTED"):
        world.loop.start()

    assert len(FakeServer.instances) == 1
    assert len(world.launcher.calls) == 1
    assert len(world.queue.bundles) == 1
    assert prekeys.public_entries() == entries
    assert not sk_c2t.wiped
    assert world.server.kwargs["sessions"].get(SESSION_ID) is not None
    assert world.loop.tick().processed == 0  # still the same live loop


def test_c13_start_after_shutdown_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(monkeypatch)
    world.loop.shutdown()

    with pytest.raises(RuntimeError, match="ALREADY_STARTED"):
        world.loop.start()

    assert len(world.launcher.calls) == 1
    with pytest.raises(RuntimeError, match="NOT_STARTED"):
        world.loop.tick()


# ---------------------------------------------------------------- criterion 14 (A1): queue errors
def unavailable() -> QueueError:
    return QueueError(QueueErrorCode.UNAVAILABLE)


def test_c14_one_unavailable_on_republish_is_absorbed_and_the_republish_stays_due(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS)
    world.clock.now += 1
    burn(world, 1)  # the pre-key set changed
    world.queue.bundle_errors = [unavailable()]
    world.clock.now = START + world.limits.bundle_republish_min_interval_s

    report = world.loop.tick()  # republish fails: no exception, no pull this tick

    assert report.bundle_published is False
    assert world.queue.calls[-1][0] == "publish_bundle"
    world.clock.now += world.limits.attestation_retry_min_s
    assert world.loop.tick().bundle_published is True


def test_c14_one_unavailable_ack_ends_the_ticks_queue_work_and_the_count_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    world.queue.inbox = [message(1, b"a"), message(2, b"b")]
    world.queue.ack_errors = [unavailable()]

    report = world.loop.tick()

    assert world.server.bodies == [b"a"]  # b is redelivered later, never processed now
    assert report.processed == 1
    for _ in range(9):  # nine more failures after a success never stop the loop
        world.clock.now += world.limits.attestation_retry_max_s
        world.queue.pull_errors = [unavailable()]
        world.loop.tick()
    world.clock.now += world.limits.attestation_retry_max_s
    world.loop.tick()  # success resets the count
    world.clock.now += world.limits.attestation_retry_max_s
    world.queue.pull_errors = [unavailable()]
    world.loop.tick()
    assert world.queue.named("withdraw_bundle") == []


def test_c14_a_publish_response_failure_then_success_resets_the_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)

    def failing_pulls(n: int) -> None:
        for _ in range(n):
            world.queue.pull_errors = [unavailable()]
            world.loop.tick()
            world.clock.now += world.limits.attestation_retry_max_s

    failing_pulls(8)
    answered(world, 1, b"req")
    world.queue.publish_errors = [unavailable()]  # the 9th failure; the retry succeeds

    world.loop.tick()
    world.clock.now += world.limits.attestation_retry_max_s
    failing_pulls(9)  # would be the 19th: the count was reset

    assert len(world.queue.named("publish_response")) == 2
    assert world.queue.named("withdraw_bundle") == []


def test_c14_ten_consecutive_unavailable_across_queue_calls_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS)
    step = world.limits.attestation_retry_max_s  # every tick is past the current backoff

    def tick() -> None:
        world.clock.now += step
        world.loop.tick()

    answered(world, 1, b"req")
    world.queue.publish_errors = [unavailable(), unavailable()]
    world.queue.ack_errors = [unavailable()]
    tick()  # failures 1-3: publish, its retry, ack
    world.queue.pull_errors = [unavailable()] * 3
    for _ in range(3):
        tick()  # failures 4-6: pulls
    prekeys = world.server.kwargs["prekeys"]
    prekeys.take(prekeys.public_entries()[0].id)  # a republish is now due
    world.queue.bundle_errors = [unavailable()] * 4
    for _ in range(3):
        tick()  # failures 7-9: republishes
    assert world.queue.named("withdraw_bundle") == []

    with pytest.raises(WorkloadStopped) as stopped:
        tick()  # failure 10

    assert stopped.value.code is StopCode.QUEUE_UNAVAILABLE
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]
    assert world.queue.bundles[-1:] == world.queue.bundles[:1]  # never republished


@pytest.mark.parametrize("call", ["bundle", "pull", "publish", "ack"])
def test_c14_any_other_queue_error_stops_at_once(
    monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    world = World(monkeypatch, params=BURN_PARAMS)
    world.clock.now += 1
    burn(world, 1)
    world.clock.now = START + world.limits.bundle_republish_min_interval_s
    answered(world, 7, b"req")
    getattr(
        world.queue,
        {
            "bundle": "bundle_errors",
            "pull": "pull_errors",
            "publish": "publish_errors",
            "ack": "ack_errors",
        }[call],
    ).append(QueueError(QueueErrorCode.INTERNAL))

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.tick()

    assert stopped.value.code is StopCode.QUEUE_UNAVAILABLE
    assert world.queue.named("withdraw_bundle") == [("withdraw_bundle", world.loop.instance_id)]


def test_c14_an_unavailable_queue_at_start_defers_the_first_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, start=False)
    world.queue.bundle_errors = [unavailable()]

    world.loop.start()

    assert world.queue.bundles == []
    world.clock.now += world.limits.attestation_retry_min_s
    assert world.loop.tick().bundle_published is True
    assert len(world.queue.bundles) == 1


def test_c14_a_failing_withdraw_in_run_is_reported_as_a_stop_not_a_raw_queue_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch, start=False)
    stop = threading.Event()
    stop.set()

    def failing(instance_id: str) -> None:
        raise unavailable()

    monkeypatch.setattr(world.queue, "withdraw_bundle", failing)

    with pytest.raises(WorkloadStopped) as stopped:
        world.loop.run(stop)

    assert stopped.value.code is StopCode.QUEUE_UNAVAILABLE


# ---------------------------------------------------------------- criterion 15 (A1): idle first
def test_c15_a_session_idle_for_exactly_the_timeout_is_closed_before_its_frame_is_pulled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World(monkeypatch)
    open_session(world)
    world.clock.now += PARAMS.idle_timeout_s
    sessions = world.server.kwargs["sessions"]
    seen: list[tuple[bool, list[tuple[SessionInfo, CloseReason]]]] = []
    world.server.on_process = lambda _body: seen.append(
        (sessions.get(SESSION_ID) is None, list(world.opener.closed_calls))
    )
    world.queue.inbox.append(message(1, b"frame-for-the-idle-session"))

    world.loop.tick()

    info = SessionInfo(CLIENT, SESSION_ID, world.loop.instance_id)
    assert seen == [(True, [(info, CloseReason.IDLE_TIMEOUT)])]  # server answers SESSION_UNKNOWN
