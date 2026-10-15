"""In-memory queue and audit sink for the simulator (INC-2-API §5.1; spec §15.2 item 5; D2-11).

Development only: never a dependency of `teecustody`. Bodies belong to T-24.
"""

import os
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from teecustody.audit import (
    AppendResult,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    validate_audit,
)
from teecustody.channel.codec import CLIENT_ID_PATTERN, INSTANCE_ID_PATTERN
from teecustody.queue import (
    RELAY_ID_PATTERN,
    PublishedBundle,
    PublishedResponse,
    QueueError,
    QueueErrorCode,
    QueueMessage,
    ResponsePage,
)

_NAMESPACE_PATTERN: Final = re.compile(r"[a-z][a-z0-9-]{0,31}")  # fullmatch only (R-7)
_MIN_COUNT: Final = 1  # max_messages / max_bundles per call
_MAX_COUNT: Final = 1000
_MAX_WAIT_S: Final = 30.0
# Response cursor: the decimal per-client sequence number of the last returned response.
_CURSOR_PATTERN: Final = re.compile(r"0|[1-9][0-9]{0,19}")  # fullmatch only (R-7)


def _check_id(pattern: re.Pattern[str], value: object) -> None:
    if not (isinstance(value, str) and pattern.fullmatch(value)):
        raise QueueError(QueueErrorCode.INVALID_ARGUMENT)


def _check_count(value: object) -> None:
    if not (type(value) is int and _MIN_COUNT <= value <= _MAX_COUNT):
        raise QueueError(QueueErrorCode.INVALID_ARGUMENT)


def _check_wait(value: object) -> None:
    in_range = isinstance(value, int | float) and 0 <= value <= _MAX_WAIT_S
    if isinstance(value, bool) or not in_range:
        raise QueueError(QueueErrorCode.INVALID_ARGUMENT)


@dataclass(frozen=True, slots=True)
class _Response:
    seq: int
    published_at: float
    response: PublishedResponse


@dataclass(slots=True)
class _Route:
    last_seq: int = 0
    responses: deque[_Response] = field(default_factory=deque)


@dataclass(slots=True)
class _Request:
    instance_id: str
    message: QueueMessage
    visible_at: float = field(default=float("-inf"))


class InMemoryQueue:
    """Implements `teecustody.queue.Queue`; thread-safe."""

    def __init__(
        self,
        *,
        namespace: str = "sim",
        ack_deadline_s: float = 30.0,
        request_retention_s: float = 300.0,
        response_retention_s: float = 300.0,
        max_topic_depth: int = 10_000,
        max_bundles: int = 64,
        clock: Callable[[], float] = time.time,
        rng: Callable[[int], bytes] = os.urandom,
    ) -> None:
        if not _NAMESPACE_PATTERN.fullmatch(namespace):
            raise ValueError("NAMESPACE")
        self._namespace = namespace
        self._ack_deadline_s = ack_deadline_s
        self._request_retention_s = request_retention_s
        self._response_retention_s = response_retention_s
        self._max_topic_depth = max_topic_depth
        self._max_bundles = max_bundles
        self._clock = clock
        self._rng = rng
        self._cond = threading.Condition()
        self._bundles: dict[str, tuple[bytes, int]] = {}
        self._requests: dict[str, _Request] = {}
        self._routes: dict[str, _Route] = {}
        self._response_depth = 0
        self._responses_issued = 0

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        _check_id(INSTANCE_ID_PATTERN, instance_id)
        if type(expires_at) is not int:
            raise QueueError(QueueErrorCode.INVALID_ARGUMENT)
        with self._cond:
            now = self._clock()
            self._purge(now)
            if expires_at <= now:
                raise QueueError(QueueErrorCode.INVALID_ARGUMENT)
            if instance_id not in self._bundles and len(self._bundles) >= self._max_bundles:
                raise QueueError(QueueErrorCode.UNAVAILABLE)
            self._bundles[instance_id] = (bundle, expires_at)

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        _check_id(INSTANCE_ID_PATTERN, instance_id)
        _check_count(max_messages)
        _check_wait(wait_s)
        deadline = time.monotonic() + wait_s
        with self._cond:
            while True:
                now = self._clock()
                self._purge(now)
                due = self._visible(instance_id, now)[:max_messages]
                remaining = deadline - time.monotonic()
                if due or remaining <= 0:
                    break
                self._cond.wait(remaining)
            for request in due:
                request.visible_at = now + self._ack_deadline_s
            return [request.message for request in due]

    def ack(self, message_id: str) -> None:
        _check_id(RELAY_ID_PATTERN, message_id)
        with self._cond:
            self._purge(self._clock())
            self._requests.pop(message_id, None)

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        _check_id(CLIENT_ID_PATTERN, client_id)
        _check_id(RELAY_ID_PATTERN, request_id)
        with self._cond:
            now = self._clock()
            self._purge(now)
            if self._response_depth >= self._max_topic_depth:
                raise QueueError(QueueErrorCode.UNAVAILABLE)
            route = self._route(client_id)
            self._routes[client_id] = route
            route.last_seq += 1
            self._responses_issued += 1
            route.responses.append(
                _Response(route.last_seq, now, PublishedResponse(request_id, body))
            )
            self._response_depth += 1

    def withdraw_bundle(self, instance_id: str) -> None:
        _check_id(INSTANCE_ID_PATTERN, instance_id)
        with self._cond:
            self._purge(self._clock())
            self._bundles.pop(instance_id, None)

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        _check_count(max_bundles)
        with self._cond:
            self._purge(self._clock())
            live = sorted(self._bundles.items())[:max_bundles]
            return [PublishedBundle(instance_id, bundle) for instance_id, (bundle, _) in live]

    def _visible(self, instance_id: str, now: float) -> list[_Request]:
        return [
            request
            for request in self._requests.values()
            if request.instance_id == instance_id and request.visible_at <= now
        ]

    def _purge(self, now: float) -> None:
        expired = [iid for iid, (_, expires_at) in self._bundles.items() if expires_at <= now]
        for instance_id in expired:
            del self._bundles[instance_id]
        stale = [
            message_id
            for message_id, request in self._requests.items()
            if now - request.message.published_at >= self._request_retention_s
        ]
        for message_id in stale:
            del self._requests[message_id]
        for client_id, route in list(self._routes.items()):
            while (
                route.responses
                and now - route.responses[0].published_at >= self._response_retention_s
            ):
                route.responses.popleft()
                self._response_depth -= 1
            if not route.responses:
                del self._routes[client_id]

    def _route(self, client_id: str) -> _Route:
        # A route without responses is not stored (SR-4). It (re)starts above every sequence issued
        # so far, so a cursor from a drained route stays valid and sees only newer responses.
        route = self._routes.get(client_id)
        return _Route(last_seq=self._responses_issued) if route is None else route

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        _check_id(INSTANCE_ID_PATTERN, instance_id)
        _check_id(RELAY_ID_PATTERN, request_id)
        with self._cond:
            now = self._clock()
            self._purge(now)
            if instance_id not in self._bundles:
                raise QueueError(QueueErrorCode.NOT_FOUND)
            if len(self._requests) >= self._max_topic_depth:
                raise QueueError(QueueErrorCode.UNAVAILABLE)
            message_id = self._rng(16).hex()
            message = QueueMessage(message_id, request_id, body, now)
            self._requests[message_id] = _Request(instance_id, message)
            self._cond.notify_all()
            return message_id

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        _check_id(CLIENT_ID_PATTERN, client_id)
        _check_count(max_messages)
        with self._cond:
            self._purge(self._clock())
            route = self._route(client_id)
            if after is None:
                floor = 0
            elif _CURSOR_PATTERN.fullmatch(after) and int(after) <= route.last_seq:
                floor = int(after)
            else:
                raise QueueError(QueueErrorCode.INVALID_ARGUMENT)
            page = [entry for entry in route.responses if entry.seq > floor][:max_messages]
            if not page:
                return ResponsePage((), None)
            return ResponsePage(tuple(entry.response for entry in page), str(page[-1].seq))


class InMemoryAuditSink:
    """Implements `teecustody.audit.AuditSink`; thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._objects: dict[AuditKey, AuditRecord] = {}
        self._fail_remaining = 0
        self._fail_code = AuditErrorCode.UNAVAILABLE

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        validate_audit(key, record)
        with self._lock:
            if self._fail_remaining > 0:
                self._fail_remaining -= 1
                raise AuditError(self._fail_code)
            if key in self._objects:
                return AppendResult.ALREADY_EXISTS
            self._objects[key] = record
            return AppendResult.CREATED

    def records(self, record_class: AuditClass | None = None) -> list[tuple[AuditKey, AuditRecord]]:
        with self._lock:
            return [
                (key, record)
                for key, record in self._objects.items()
                if record_class is None or key.record_class is record_class
            ]

    def fail_next(self, n: int, code: AuditErrorCode = AuditErrorCode.UNAVAILABLE) -> None:
        if type(n) is not int or n < 0:
            raise ValueError("FAIL_NEXT")
        with self._lock:
            self._fail_remaining = n
            self._fail_code = code
