"""Audit emitter: aggregates, capped pre-principal alerts, retries (INC-2-API §4.12, §10).

`AggregateOutcome` is frozen; bodies belong to T-12.
"""

from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Final

from teecustody.audit.ports import (
    MAX_COUNT,
    AppendResult,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    AuditSink,
)
from teecustody.obs.types import OUTCOME_PATTERN, AllowListedLogger

_CONFLICT = "AUDIT_WRITE_CONFLICT"


class AggregateOutcome(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    REQUEST_WRONG_INSTANCE = "REQUEST_WRONG_INSTANCE"
    PREKEY_UNKNOWN = "PREKEY_UNKNOWN"
    REQUEST_STALE = "REQUEST_STALE"
    REQUEST_REPLAYED = "REQUEST_REPLAYED"
    OPEN_FAILED = "OPEN_FAILED"
    OPEN_PAYLOAD_INVALID = "OPEN_PAYLOAD_INVALID"
    OPEN_REJECTED = "OPEN_REJECTED"
    SESSION_UNKNOWN = "SESSION_UNKNOWN"
    FRAME_SEQ_REJECTED = "FRAME_SEQ_REJECTED"
    FRAME_AUTH_FAILED = "FRAME_AUTH_FAILED"
    CHANNEL_LIMIT_EXCEEDED = "CHANNEL_LIMIT_EXCEEDED"


_PENDING_MAX: Final = 2 * len(AggregateOutcome)
PROTECTED_PENDING_MAX: Final = 256


def _drop_log(outcome: str) -> str:
    named = f"AUDIT_PENDING_DROPPED_{outcome}"
    return named if OUTCOME_PATTERN.fullmatch(named) else "AUDIT_PENDING_DROPPED"


class AuditEmitter:
    def __init__(
        self,
        sink: AuditSink,
        *,
        interval_s: int,
        alert_cap: int,
        clock: Callable[[], float],
        rng: Callable[[int], bytes],
        logger: AllowListedLogger,
    ) -> None:
        self._sink = sink
        self._interval_ms = interval_s * 1000
        self._alert_cap = alert_cap
        self._clock = clock
        self._rng = rng
        self._logger = logger
        self._start = self._now_ms()
        self._counts: dict[str, int] = {}
        self._alerted: set[tuple[str, str]] = set()
        self._cap_reached = False
        self._protected: deque[tuple[AuditKey, AuditRecord]] = deque()
        self._sheddable: deque[tuple[AuditKey, AuditRecord]] = deque()

    def _now_ms(self) -> int:
        return int(self._clock() * 1000)

    def count(self, outcome: AggregateOutcome) -> None:
        self._fold(outcome.value)

    def _fold(self, outcome: str) -> None:
        self._counts[outcome] = min(self._counts.get(outcome, 0) + 1, MAX_COUNT)

    def pre_principal_alert(
        self,
        outcome: str,
        *,
        subject_client_id: str,
        request_id: str | None = None,
        epoch: int | None = None,
        recovery_id: str | None = None,
    ) -> None:
        if (outcome, subject_client_id) in self._alerted:
            self._fold(outcome)
            return
        if len(self._alerted) >= self._alert_cap:
            if not self._cap_reached:
                self._cap_reached = True
                self.alert("ALERT_CAP_REACHED")
            self._fold(outcome)
            return
        self._alerted.add((outcome, subject_client_id))
        record = AuditRecord(
            outcome=outcome,
            ts=self._now_ms(),
            subject_client_id=subject_client_id,
            request_id=request_id,
            epoch=epoch,
            recovery_id=recovery_id,
        )
        self._write(self._alert_key(outcome), record, protected=False)

    def _alert_key(self, outcome: str) -> AuditKey:
        return AuditKey(AuditClass.ALERT, f"{self._rng(16).hex()}/{outcome}")

    def _write(self, key: AuditKey, record: AuditRecord, *, protected: bool) -> None:
        """Protected records (`alert()`) never share a bound with anonymous-driven ones (SR-12)."""
        if self._attempt(key, record):
            return
        pending, bound = (
            (self._protected, PROTECTED_PENDING_MAX)
            if protected
            else (self._sheddable, _PENDING_MAX)
        )
        pending.append((key, record))
        if len(pending) > bound:
            _, dropped = pending.popleft()
            self._logger.warning(_drop_log(dropped.outcome))

    def _attempt(self, key: AuditKey, record: AuditRecord) -> bool:
        """Append once; False iff the sink is UNAVAILABLE and the record should stay pending."""
        try:
            result = self._sink.append(key, record)
        except Exception as err:  # noqa: BLE001 - never raise into the channel; detail never logged
            if isinstance(err, AuditError) and err.code is AuditErrorCode.UNAVAILABLE:
                return False
            self._logger.error("AUDIT_WRITE_FAILED")
            return True
        if result is AppendResult.ALREADY_EXISTS:
            if record.outcome == _CONFLICT:
                self._logger.error("AUDIT_WRITE_FAILED")
            else:
                self.alert(_CONFLICT, request_id=record.request_id)
        return True

    def _retry_pending(self) -> None:
        for pending in (self._protected, self._sheddable):
            while pending:
                key, record = pending.popleft()
                if not self._attempt(key, record):
                    pending.appendleft((key, record))
                    return

    def alert(
        self,
        outcome: str,
        *,
        request_id: str | None = None,
        interval: tuple[int, int] | None = None,
    ) -> None:
        start, end = interval if interval is not None else (None, None)
        self._write(
            self._alert_key(outcome),
            AuditRecord(
                outcome=outcome,
                ts=self._now_ms(),
                request_id=request_id,
                interval_start=start,
                interval_end=end,
            ),
            protected=True,
        )

    def tick(self) -> None:
        self._retry_pending()
        now = self._now_ms()
        end = self._start + self._interval_ms
        if now >= end:
            self._flush(end, now)
            skipped = (now - self._start) // self._interval_ms  # empty intervals after a clock jump
            self._start += skipped * self._interval_ms

    def close(self) -> None:
        self.tick()
        now = self._now_ms()
        self._flush(max(now, self._start + 1), now)  # interval_start < interval_end always

    def _flush(self, end: int, now: int) -> None:
        for outcome, n in self._counts.items():
            key = AuditKey(AuditClass.AGGREGATE, f"{self._start}/{outcome}/{self._rng(8).hex()}")
            record = AuditRecord(
                outcome=outcome, ts=now, interval_start=self._start, interval_end=end, count=n
            )
            self._write(key, record, protected=False)
        self._counts = {}
        self._alerted = set()
        self._cap_reached = False
        self._start = end
