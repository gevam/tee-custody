"""Channel port doubles for INC-2 tests only (INC-2-API §5.2, D2-10). Never shipped.

`packages/**` must not import this module and must not define a class named `StaticShareOpener`
(semgrep `tc-py-no-test-doubles`). INC-3 custody replaces these with the real `SessionOpener` and
dispatcher.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Mapping

from teecustody.channel.ports import (
    CloseReason,
    EnrollPayload,
    FrameResultBody,
    HandlerError,
    HandlerOk,
    OpenAccepted,
    OpenRejected,
    OpenRequest,
    OpenResult,
    OpenSessionPayload,
    RemoteErrorCode,
    SessionInfo,
)
from teecustody.wire import CanonicalValue


class _RecordingOpener:
    """Records every `OpenRequest` and every `closed` call for assertions."""

    def __init__(self) -> None:
        self.requests: list[OpenRequest] = []
        self.closed_calls: list[tuple[bytes, CloseReason]] = []

    def closed(self, session: SessionInfo, reason: CloseReason) -> None:
        self.closed_calls.append((session.session_id, reason))


class StaticShareOpener(_RecordingOpener):
    """open_session is accepted iff `cs` equals the configured share of the claimed client."""

    def __init__(self, shares: Mapping[str, bytes]) -> None:
        super().__init__()
        self._shares = dict(shares)

    def open(self, request: OpenRequest) -> OpenResult:
        self.requests.append(request)
        payload = request.payload
        if isinstance(payload, EnrollPayload):
            return OpenRejected(RemoteErrorCode.UNKNOWN_OPERATION)
        assert isinstance(payload, OpenSessionPayload)
        claimed = request.claimed_client_id
        expected = self._shares.get(claimed) if claimed is not None else None
        if expected is None or not hmac.compare_digest(payload.cs.reveal(), expected):
            return OpenRejected(RemoteErrorCode.AUTHENTICATION_FAILED)
        assert claimed is not None
        return OpenAccepted(client_id=claimed, payload=None)


class MismatchingOpener(_RecordingOpener):
    """Accepts every open with a fixed principal that differs from the claim (SR-14 R-4 test)."""

    def __init__(self, principal: str) -> None:
        super().__init__()
        self._principal = principal

    def open(self, request: OpenRequest) -> OpenResult:
        self.requests.append(request)
        return OpenAccepted(client_id=self._principal, payload=None)


class EnrollingOpener(_RecordingOpener):
    """enroll → a freshly minted random principal; open_session → AUTHENTICATION_FAILED."""

    def __init__(self) -> None:
        super().__init__()
        self.minted: list[str] = []

    def open(self, request: OpenRequest) -> OpenResult:
        self.requests.append(request)
        if not isinstance(request.payload, EnrollPayload):
            return OpenRejected(RemoteErrorCode.AUTHENTICATION_FAILED)
        principal = os.urandom(16).hex()
        self.minted.append(principal)
        return OpenAccepted(client_id=principal, payload={"client_id": principal})


class EchoHandler:
    """FrameHandler: op "test.echo" returns its payload; every other op is UNKNOWN_OPERATION."""

    def __init__(self) -> None:
        self.calls: list[tuple[SessionInfo, str, CanonicalValue]] = []

    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody:
        self.calls.append((session, op, payload))
        if op == "test.echo":
            return HandlerOk(payload)
        return HandlerError(RemoteErrorCode.UNKNOWN_OPERATION)
