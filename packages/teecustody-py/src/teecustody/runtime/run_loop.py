"""Workload run loop (INC-2-API §4.13; spec §5.1, §11; B-08).

`StopCode`, `WorkloadStopped` and `TickReport` are frozen; bodies belong to T-29.
"""

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from teecustody.attest.lifecycle import RefreshOutcome
from teecustody.attest.ports import Launcher
from teecustody.audit.ports import AuditSink
from teecustody.channel.ports import FrameHandler, SessionOpener
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.obs.types import AllowListedLogger
from teecustody.queue.ports import WorkloadQueue

_DEFAULT_PARAMS = ChannelParams()
_DEFAULT_LIMITS = BoundaryLimits()


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


class RunLoop:
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
        raise NotImplementedError("T-29")

    @property
    def instance_id(self) -> str:
        raise NotImplementedError("T-29")

    def start(self) -> None:
        raise NotImplementedError("T-29")

    def tick(self) -> TickReport:
        raise NotImplementedError("T-29")

    def run(self, stop: threading.Event) -> None:
        raise NotImplementedError("T-29")

    def shutdown(self) -> None:
        raise NotImplementedError("T-29")
