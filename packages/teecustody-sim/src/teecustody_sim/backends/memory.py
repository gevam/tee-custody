"""In-memory queue and audit sink for the simulator (INC-2-API §5.1; spec §15.2 item 5; D2-11).

Development only: never a dependency of `teecustody`. Bodies belong to T-24.
"""

import os
import threading
import time
from collections.abc import Callable

from teecustody.audit import AppendResult, AuditClass, AuditErrorCode, AuditKey, AuditRecord
from teecustody.queue import PublishedBundle, QueueMessage, ResponsePage


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
        self._clock = clock
        self._cond = threading.Condition()
        self._bundles: dict[str, tuple[bytes, int]] = {}

    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
        with self._cond:
            self._bundles[instance_id] = (bundle, expires_at)

    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]:
        raise NotImplementedError("T-24")

    def ack(self, message_id: str) -> None:
        raise NotImplementedError("T-24")

    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None:
        raise NotImplementedError("T-24")

    def withdraw_bundle(self, instance_id: str) -> None:
        with self._cond:
            self._bundles.pop(instance_id, None)

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        with self._cond:
            self._purge(self._clock())
            live = sorted(self._bundles.items())[:max_bundles]
            return [PublishedBundle(instance_id, bundle) for instance_id, (bundle, _) in live]

    def _purge(self, now: float) -> None:
        expired = [iid for iid, (_, expires_at) in self._bundles.items() if expires_at <= now]
        for instance_id in expired:
            del self._bundles[instance_id]

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        raise NotImplementedError("T-24")

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        raise NotImplementedError("T-24")


class InMemoryAuditSink:
    """Implements `teecustody.audit.AuditSink`; thread-safe."""

    def __init__(self) -> None:
        raise NotImplementedError("T-24")

    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult:
        raise NotImplementedError("T-24")

    def records(self, record_class: AuditClass | None = None) -> list[tuple[AuditKey, AuditRecord]]:
        raise NotImplementedError("T-24")

    def fail_next(self, n: int, code: AuditErrorCode = AuditErrorCode.UNAVAILABLE) -> None:
        raise NotImplementedError("T-24")
