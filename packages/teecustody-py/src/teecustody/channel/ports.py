"""Channel ports implemented by INC-3 custody and dispatch (INC-2-API §4.8; D2-10, R-4).

`OpenSessionPayload` and `EnrollPayload` are defined here (codec.py re-exports them) to avoid an
import cycle.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from teecustody.secrets import Secret
from teecustody.wire.types import CanonicalValue


class RemoteErrorCode(StrEnum):
    INVALID_FRAME = "INVALID_FRAME"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    REPLAYED_OR_OUT_OF_ORDER = "REPLAYED_OR_OUT_OF_ORDER"
    UNKNOWN_CLIENT = "UNKNOWN_CLIENT"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    INTERNAL = "INTERNAL"


@dataclass(frozen=True, slots=True, eq=False)
class OpenSessionPayload:
    cs: Secret
    key_id: bytes
    epoch: int


@dataclass(frozen=True, slots=True)
class EnrollPayload:
    pass


@dataclass(frozen=True, slots=True, eq=False)
class OpenRequest:
    # open_session: the AAD client_id, a CLAIM the opener must prove (kcv, INC-3).
    # enroll: always None. The reply route is never passed to the opener (R-4).
    claimed_client_id: str | None
    request_id: bytes
    instance_id: str
    session_id: bytes  # pre-minted; becomes the session id if accepted
    payload: OpenSessionPayload | EnrollPayload


@dataclass(frozen=True, slots=True)
class OpenAccepted:
    client_id: str  # the principal (the minted one for enroll)
    payload: CanonicalValue


@dataclass(frozen=True, slots=True)
class OpenRejected:
    error: RemoteErrorCode


type OpenResult = OpenAccepted | OpenRejected


@dataclass(frozen=True, slots=True)
class SessionInfo:
    client_id: str
    session_id: bytes
    instance_id: str


class CloseReason(StrEnum):
    CLIENT_CLOSE = "CLIENT_CLOSE"
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    REPLACED = "REPLACED"
    SEQUENCE_EXHAUSTED = "SEQUENCE_EXHAUSTED"
    SHUTDOWN = "SHUTDOWN"
    EVICTED = "EVICTED"  # R-8: table full, least-recently-active idle session evicted
    OPEN_ABORTED = "OPEN_ABORTED"  # accepted by the opener, then refused by the channel


class SessionOpener(Protocol):
    def open(self, request: OpenRequest) -> OpenResult: ...

    def closed(self, session: SessionInfo, reason: CloseReason) -> None: ...


@dataclass(frozen=True, slots=True)
class HandlerOk:
    payload: CanonicalValue


@dataclass(frozen=True, slots=True)
class HandlerError:
    error: RemoteErrorCode


type FrameResultBody = HandlerOk | HandlerError


class FrameHandler(Protocol):
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody: ...
