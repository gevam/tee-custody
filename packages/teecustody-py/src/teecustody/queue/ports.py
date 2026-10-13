"""Queue ports: the workload side and the relay (gateway) side (INC-2-API §4.11; spec §9; D2-12)."""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol

# Relay request id and message id; fullmatch only (R-7).
RELAY_ID_PATTERN: Final = re.compile(r"[0-9a-f]{32}")
CURSOR_PATTERN: Final = re.compile(r"[A-Za-z0-9_-]{1,128}")  # fullmatch only


class QueueErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    UNAVAILABLE = "UNAVAILABLE"
    INTERNAL = "INTERNAL"


class QueueError(Exception):
    """Carries only a stable code, never a body; `str(err)` is the code value."""

    code: QueueErrorCode

    def __init__(self, code: QueueErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


@dataclass(frozen=True, slots=True)
class PublishedBundle:
    instance_id: str
    bundle: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class QueueMessage:
    message_id: str
    request_id: str
    body: bytes = field(repr=False)
    published_at: float


@dataclass(frozen=True, slots=True)
class PublishedResponse:
    request_id: str
    body: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ResponsePage:
    responses: tuple[PublishedResponse, ...]
    next: str | None


class WorkloadQueue(Protocol):
    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None: ...

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]: ...

    def ack(self, message_id: str) -> None: ...

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None: ...

    def withdraw_bundle(self, instance_id: str) -> None: ...


class RelayQueue(Protocol):
    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]: ...

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str: ...

    def pull_responses(
        self, client_id: str, after: str | None, max_messages: int
    ) -> ResponsePage: ...


class Queue(WorkloadQueue, RelayQueue, Protocol): ...
