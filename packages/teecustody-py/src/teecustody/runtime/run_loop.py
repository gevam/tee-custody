"""Workload run loop (INC-2-API §4.13; spec §5.1, §11; B-08).

`StopCode`, `WorkloadStopped` and `TickReport` are frozen; bodies belong to T-29.
"""

import contextlib
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NoReturn

from teecustody.attest.claims import own_image_digest
from teecustody.attest.lifecycle import AttestationLifecycle, RefreshOutcome
from teecustody.attest.ports import AttestationToken, Launcher, LauncherError
from teecustody.audit.emitter import AuditEmitter
from teecustody.audit.ports import AuditSink
from teecustody.channel.bundle import build_bundle
from teecustody.channel.identity import IdentityKey
from teecustody.channel.ports import CloseReason, FrameHandler, SessionInfo, SessionOpener
from teecustody.channel.prekeys import PreKeyPublic, PreKeyStore
from teecustody.channel.replay import ReplayCache
from teecustody.channel.server import ChannelServer
from teecustody.channel.session import SessionTable
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.obs.logger import get_logger
from teecustody.obs.types import AllowListedLogger
from teecustody.queue.ports import QueueError, QueueErrorCode, QueueMessage, WorkloadQueue

_DEFAULT_PARAMS = ChannelParams()
_DEFAULT_LIMITS = BoundaryLimits()
_MAX_PULL_FAILURES: Final = 10  # consecutive UNAVAILABLE pulls before QUEUE_UNAVAILABLE


def _ms(seconds: float) -> int:
    return int(seconds * 1000)


class StopCode(StrEnum):
    ATTESTATION_EXPIRED = "ATTESTATION_EXPIRED"
    DIGEST_CHANGED = "DIGEST_CHANGED"
    PREKEY_IDS_EXHAUSTED = "PREKEY_IDS_EXHAUSTED"
    QUEUE_UNAVAILABLE = "QUEUE_UNAVAILABLE"


class WorkloadStopped(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: StopCode

    def __init__(self, code: StopCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class TickReport:
    refresh: RefreshOutcome | None
    bundle_published: bool
    processed: int


@dataclass(slots=True, eq=False)
class _Live:
    """Everything `start()` builds; present from start until shutdown."""

    ik: IdentityKey
    lifecycle: AttestationLifecycle
    digest: str
    prekeys: PreKeyStore
    audit: AuditEmitter
    sessions: SessionTable
    server: ChannelServer
    burn_start: float
    published: tuple[PreKeyPublic, ...] = ()
    published_at: float = float("-inf")
    token_refreshed: bool = False


class RunLoop:
    """Single-threaded workload loop (INC-2-API §4.13); T-23's classes rely on one thread."""

    def __init__(
        self,
        *,
        launcher: Launcher,
        queue: WorkloadQueue,
        audit_sink: AuditSink,
        opener: SessionOpener,
        handler: FrameHandler,
        audience: str,
        token_type: str,
        params: ChannelParams = _DEFAULT_PARAMS,
        limits: BoundaryLimits = _DEFAULT_LIMITS,
        clock: Callable[[], float] = time.time,
        rng: Callable[[int], bytes] = os.urandom,
        logger: AllowListedLogger | None = None,
    ) -> None:
        self._launcher = launcher
        self._queue = queue
        self._audit_sink = audit_sink
        self._opener = opener
        self._handler = handler
        self._audience = audience
        self._token_type = token_type
        self._params = params
        self._limits = limits
        self._clock = clock
        self._rng = rng
        self._logger = logger if logger is not None else get_logger("runtime")
        self._instance_id = rng(16).hex()
        self._live: _Live | None = None
        self._refresh_failures = 0
        self._next_refresh_attempt_at = float("-inf")
        self._pull_failures = 0
        self._next_pull_at = float("-inf")

    @property
    def instance_id(self) -> str:
        return self._instance_id

    def start(self) -> None:
        ik = IdentityKey.generate()
        lifecycle = AttestationLifecycle(
            self._launcher,
            audience=self._audience,
            token_type=self._token_type,
            identity_public_key=ik.public_bytes(),
            refresh_margin_s=self._params.refresh_margin_s,
            clock=self._clock,
            logger=self._logger,
        )
        token = lifecycle.start()
        digest = own_image_digest(token, max_token_bytes=self._limits.max_token_bytes)
        prekeys = PreKeyStore(
            instance_id=self._instance_id,
            identity=ik,
            image_digest=digest,
            params=self._params,
            clock=self._clock,
        )
        audit = AuditEmitter(
            self._audit_sink,
            interval_s=self._limits.audit_aggregate_interval_s,
            alert_cap=self._limits.audit_alert_cap,
            clock=self._clock,
            rng=self._rng,
            logger=self._logger,
        )
        sessions = SessionTable(
            instance_id=self._instance_id,
            max_sessions=self._limits.max_sessions,
            idle_timeout_s=self._params.idle_timeout_s,
            evict_min_idle_s=self._limits.session_evict_min_idle_s,
            on_close=self._on_close,
            clock=self._clock,
        )
        server = ChannelServer(
            instance_id=self._instance_id,
            ik_pub=ik.public_bytes(),
            prekeys=prekeys,
            sessions=sessions,
            replay=ReplayCache(
                skew_s=self._params.request_skew_s,
                max_entries=self._limits.replay_cache_max_entries,
                clock=self._clock,
            ),
            opener=self._opener,
            handler=self._handler,
            audit=audit,
            params=self._params,
            limits=self._limits,
            clock=self._clock,
            rng=self._rng,
            logger=self._logger,
        )
        live = _Live(ik, lifecycle, digest, prekeys, audit, sessions, server, self._clock())
        self._live = live
        prekeys.top_up()
        self._publish(live, token)

    def _publish(self, live: _Live, token: AttestationToken) -> None:
        entries = live.prekeys.public_entries()
        body = build_bundle(
            instance_id=self._instance_id,
            token=token,
            ik_pub=live.ik.public_bytes(),
            prekeys=entries,
            published_at=int(self._clock()),
        )
        expires_at = min(token.expires_at, max(p.not_after for p in entries))  # TL-3
        self._queue.publish_bundle(self._instance_id, body, expires_at)
        live.published = entries
        live.published_at = self._clock()
        live.token_refreshed = False
        self._logger.info("BUNDLE_PUBLISHED")

    def _on_close(self, info: SessionInfo, reason: CloseReason) -> None:
        """TL-2: the one place a session close is logged and reported to the opener."""
        outcome = "SESSION_EVICTED" if reason is CloseReason.EVICTED else "SESSION_CLOSED"
        self._logger.info(outcome, client_id=info.client_id, session_id=info.session_id.hex())
        with contextlib.suppress(Exception):
            self._opener.closed(info, reason)

    def tick(self) -> TickReport:
        live = self._require_live()
        refresh = self._refresh(live)
        live.token_refreshed |= refresh is RefreshOutcome.REFRESHED
        live.prekeys.expire()
        live.prekeys.top_up()
        bundle_published = self._republish_if_changed(live)
        processed = 0
        for message in self._pull():
            self._handle(live, message)
            processed += 1
        self._check_burn(live)
        return TickReport(refresh=refresh, bundle_published=bundle_published, processed=processed)

    def _republish_if_changed(self, live: _Live) -> bool:
        """(3) new token or changed pre-key set; at most once per republish min interval."""
        changed = live.token_refreshed or live.prekeys.public_entries() != live.published
        due = self._clock() - live.published_at >= self._limits.bundle_republish_min_interval_s
        if not (changed and due):
            return False
        self._publish(live, live.lifecycle.current())
        return True

    def _check_burn(self, live: _Live) -> None:
        """(6) SR-12: one PREKEY_BURN_HIGH per ended interval whose own consumption is too high."""
        now = self._clock()
        interval = self._limits.audit_aggregate_interval_s
        consumed_since = live.prekeys.consumed_since
        while now >= live.burn_start + interval:
            start, end = live.burn_start, live.burn_start + interval
            if (
                consumed_since(start) - consumed_since(end)
                > self._limits.prekey_burn_alert_threshold
            ):
                live.audit.alert("PREKEY_BURN_HIGH", interval=(_ms(start), _ms(end)))
            # Intervals with no consumption at all are skipped in one step.
            live.burn_start = (
                end if consumed_since(end) else end + (now - end) // interval * interval
            )

    def _pull(self) -> list[QueueMessage]:
        """(4) pull; UNAVAILABLE backs off like B-08 on its own counter, and 10 in a row stop."""
        now = self._clock()
        if now < self._next_pull_at:
            return []
        try:
            messages = self._queue.pull_requests(
                self._instance_id, self._limits.pull_max_messages, self._limits.pull_wait_s
            )
        except QueueError as err:
            if err.code is not QueueErrorCode.UNAVAILABLE:
                raise
            self._logger.warning("QUEUE_PULL_FAILED")
            self._pull_failures += 1
            if self._pull_failures >= _MAX_PULL_FAILURES:
                self._stop(StopCode.QUEUE_UNAVAILABLE)
            self._next_pull_at = now + self._backoff(self._pull_failures)
            return []
        self._pull_failures = 0
        return messages

    def _handle(self, live: _Live, message: QueueMessage) -> None:
        """(4) process, respond, ack. Sealed once; a retry re-sends the same bytes (R-5)."""
        response = live.server.process(message.body).response
        if response is not None:
            for _ in range(2):
                try:
                    self._queue.publish_response(
                        response.client_id, message.request_id, response.body
                    )
                    break
                except QueueError:
                    self._logger.warning("RESPONSE_PUBLISH_FAILED")
        self._queue.ack(message.message_id)

    def _require_live(self) -> _Live:
        if self._live is None:
            raise RuntimeError("NOT_STARTED")
        return self._live

    def _refresh(self, live: _Live) -> RefreshOutcome | None:
        """(1) B-08: the launcher is never asked before `next_refresh_attempt_at`."""
        now = self._clock()
        if now < self._next_refresh_attempt_at:
            return None
        try:
            outcome = live.lifecycle.refresh_if_due()
        except LauncherError:
            self._stop(StopCode.ATTESTATION_EXPIRED)
        if outcome is RefreshOutcome.FAILED_KEPT_CURRENT:
            self._refresh_failures += 1
            self._next_refresh_attempt_at = now + self._backoff(self._refresh_failures)
        elif outcome is RefreshOutcome.REFRESHED:
            self._refresh_failures = 0
            token = live.lifecycle.current()
            if own_image_digest(token, max_token_bytes=self._limits.max_token_bytes) != live.digest:
                self._stop(StopCode.DIGEST_CHANGED)
        return outcome

    def _stop(self, code: StopCode) -> NoReturn:
        self.shutdown()
        raise WorkloadStopped(code)

    def _backoff(self, failures: int) -> int:
        """`min(retry_max, retry_min * 2^(n-1))` for the n-th consecutive failure (B-08)."""
        retry_min = self._limits.attestation_retry_min_s
        return min(self._limits.attestation_retry_max_s, retry_min << (failures - 1))

    def run(self, stop: threading.Event) -> None:
        raise NotImplementedError("T-29")

    def shutdown(self) -> None:
        """Idempotent: withdraw the bundle, close every session, wipe pre-keys, flush audit."""
        live, self._live = self._live, None
        if live is None:
            return
        self._queue.withdraw_bundle(self._instance_id)
        live.sessions.close_all()
        live.prekeys.destroy_all()
        live.audit.close()
