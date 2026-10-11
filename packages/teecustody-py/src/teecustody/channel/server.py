"""Workload channel server (INC-2-API §4.10; spec §5.4-§5.5).

`ChannelOutcome`, `OutboundResponse` and `ProcessResult` are frozen; bodies belong to T-28.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from teecustody.audit.emitter import AuditEmitter
from teecustody.channel.ports import FrameHandler, SessionOpener
from teecustody.channel.prekeys import PreKeyStore
from teecustody.channel.replay import ReplayCache
from teecustody.channel.session import SessionTable
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.obs.types import AllowListedLogger


class ChannelOutcome(StrEnum):
    SESSION_OPENED = "SESSION_OPENED"
    OPEN_REJECTED = "OPEN_REJECTED"
    FRAME_ACCEPTED = "FRAME_ACCEPTED"
    SESSION_CLOSED = "SESSION_CLOSED"
    # pre-principal outcomes are AggregateOutcome members (INC-2-API §10)


@dataclass(frozen=True, slots=True)
class OutboundResponse:
    client_id: str
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    outcome: str
    response: OutboundResponse | None


class ChannelServer:
    def __init__(
        self,
        *,
        instance_id: str,
        ik_pub: bytes,
        prekeys: PreKeyStore,
        sessions: SessionTable,
        replay: ReplayCache,
        opener: SessionOpener,
        handler: FrameHandler,
        audit: AuditEmitter,
        params: ChannelParams,
        limits: BoundaryLimits,
        clock: Callable[[], float],
        rng: Callable[[int], bytes],
        logger: AllowListedLogger,
    ) -> None:
        raise NotImplementedError("T-28")

    def process(self, body: bytes) -> ProcessResult:
        raise NotImplementedError("T-28")
