"""Audit emitter: aggregates, capped pre-principal alerts, retries (INC-2-API §4.12, §10).

`AggregateOutcome` is frozen; bodies belong to T-12.
"""

from collections.abc import Callable
from enum import StrEnum

from teecustody.audit.ports import (
    MAX_COUNT,
    AppendResult,
    AuditClass,
    AuditKey,
    AuditRecord,
    AuditSink,
)
from teecustody.obs.types import AllowListedLogger

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
        self._write(self._alert_key(outcome), record)

    def _alert_key(self, outcome: str) -> AuditKey:
        return AuditKey(AuditClass.ALERT, f"{self._rng(16).hex()}/{outcome}")

    def _write(self, key: AuditKey, record: AuditRecord) -> None:
        if self._sink.append(key, record) is not AppendResult.ALREADY_EXISTS:
            return
        if record.outcome == _CONFLICT:
            self._logger.error("AUDIT_WRITE_FAILED")
            return
        self.alert(_CONFLICT, request_id=record.request_id)

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
        )

    def tick(self) -> None:
        now = self._now_ms()
        end = self._start + self._interval_ms
        if now < end:
            return
        for outcome, n in self._counts.items():
            key = AuditKey(AuditClass.AGGREGATE, f"{self._start}/{outcome}/{self._rng(8).hex()}")
            record = AuditRecord(
                outcome=outcome, ts=now, interval_start=self._start, interval_end=end, count=n
            )
            self._write(key, record)
        self._counts = {}
        self._alerted = set()
        self._cap_reached = False
        self._start = end

    def close(self) -> None:
        raise NotImplementedError("T-12")
