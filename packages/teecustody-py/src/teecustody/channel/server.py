"""Workload channel server (INC-2-API §4.10; spec §5.4-§5.5).

`ChannelOutcome`, `OutboundResponse` and `ProcessResult` are frozen; bodies belong to T-28.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import cast

from teecustody.audit.emitter import AggregateOutcome, AuditEmitter
from teecustody.channel.codec import (
    EnvelopeError,
    OpenRequestEnvelope,
    OpenSessionPayload,
    decode_open_payload,
    decode_request,
    encode_open_result_plaintext,
    encode_response_envelope,
    hpke_info,
)
from teecustody.channel.hpke import open_base
from teecustody.channel.ports import (
    FrameHandler,
    OpenAccepted,
    OpenRequest,
    SessionOpener,
)
from teecustody.channel.prekeys import PreKeyStore
from teecustody.channel.replay import ReplayCache
from teecustody.channel.session import SessionTable, T2cSealer
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
        self._instance_id = instance_id
        self._ik_pub = ik_pub
        self._prekeys = prekeys
        self._sessions = sessions
        self._replay = replay
        self._opener = opener
        self._handler = handler
        self._audit = audit
        self._params = params
        self._limits = limits
        self._clock = clock
        self._rng = rng
        self._logger = logger

    def process(self, body: bytes) -> ProcessResult:
        now = self._clock()
        try:
            envelope = decode_request(body, self._limits)
        except EnvelopeError:
            return self._drop(AggregateOutcome.REQUEST_INVALID)
        return self._open(cast(OpenRequestEnvelope, envelope), now)

    def _drop(self, outcome: AggregateOutcome) -> ProcessResult:
        self._audit.count(outcome)
        return ProcessResult(outcome=outcome, response=None)

    def _open(self, envelope: OpenRequestEnvelope, now: float) -> ProcessResult:
        aad = envelope.aad
        if aad.instance_id != self._instance_id:
            return self._drop(AggregateOutcome.REQUEST_WRONG_INSTANCE)
        if all(entry.id != aad.prekey_id for entry in self._prekeys.public_entries()):
            return self._drop(AggregateOutcome.PREKEY_UNKNOWN)
        if abs(now - aad.timestamp) > self._params.request_skew_s:
            return self._drop(AggregateOutcome.REQUEST_STALE)
        if self._replay.seen(aad.client_id, aad.request_id):
            return self._drop(AggregateOutcome.REQUEST_REPLAYED)
        private_key = self._prekeys.take(aad.prekey_id)
        try:
            opened = open_base(
                private_key,
                envelope.enc,
                hpke_info(self._ik_pub, aad.prekey_id),
                envelope.aad_bytes,
                envelope.ct,
            )
        finally:
            private_key.wipe()
        sealer = T2cSealer(opened.sk_t2c)
        self._replay.record(aad.client_id, aad.request_id, aad.timestamp)
        payload = decode_open_payload(opened.plaintext, self._limits.open_payload_decode)
        session_id = self._rng(16)
        claimed = aad.client_id if isinstance(payload, OpenSessionPayload) else None
        result = self._opener.open(
            OpenRequest(
                claimed_client_id=claimed,
                request_id=aad.request_id,
                instance_id=self._instance_id,
                session_id=session_id,
                payload=payload,
            )
        )
        result = cast(OpenAccepted, result)
        plaintext = encode_open_result_plaintext(result)
        session = self._sessions.create(
            session_id=session_id, client_id=result.client_id, sk_c2t=opened.sk_c2t, t2c=sealer
        )
        aad_bytes, ct = session.seal_open_result(aad.request_id, plaintext)
        self._logger.info(
            "SESSION_OPENED",
            client_id=result.client_id,
            session_id=session_id.hex(),
            prekey_id=aad.prekey_id,
            request_id=aad.request_id.hex(),
        )
        return ProcessResult(
            outcome=ChannelOutcome.SESSION_OPENED,
            response=OutboundResponse(
                client_id=aad.client_id,
                body=encode_response_envelope("open_result", aad_bytes, ct),
            ),
        )
