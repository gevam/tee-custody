"""Audit emitter: aggregates, capped pre-principal alerts, retries (INC-2-API §4.12, §10).

`AggregateOutcome` is frozen; bodies belong to T-12.
"""

from collections.abc import Callable
from enum import StrEnum

from teecustody.audit.ports import AuditSink
from teecustody.obs.types import AllowListedLogger


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
        raise NotImplementedError("T-12")

    def count(self, outcome: AggregateOutcome) -> None:
        raise NotImplementedError("T-12")

    def pre_principal_alert(
        self,
        outcome: str,
        *,
        subject_client_id: str,
        request_id: str | None = None,
        epoch: int | None = None,
        recovery_id: str | None = None,
    ) -> None:
        raise NotImplementedError("T-12")

    def alert(
        self,
        outcome: str,
        *,
        request_id: str | None = None,
        interval: tuple[int, int] | None = None,
    ) -> None:
        raise NotImplementedError("T-12")

    def tick(self) -> None:
        raise NotImplementedError("T-12")

    def close(self) -> None:
        raise NotImplementedError("T-12")
