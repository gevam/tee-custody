"""T-04 criterion 1: the frozen INC-2 `teecustody_sim` API (INC-2-API §5.1, §5.3; API-TL §4).

Signatures are compared by `inspect.Signature` equality. Stub bodies are never called (D-038).
"""

from __future__ import annotations

import importlib
import inspect
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest

import teecustody_sim
from teecustody.audit import AppendResult, AuditClass, AuditErrorCode, AuditKey, AuditRecord
from teecustody.queue import PublishedBundle, Queue, QueueMessage, ResponsePage
from teecustody_sim.backends import InMemoryAuditSink, InMemoryQueue
from teecustody_sim.channel_vectors import generate_channel_suite


def test_backends_package_exports_exactly_the_in_memory_adapters() -> None:
    backends = importlib.import_module("teecustody_sim.backends")
    assert sorted(backends.__all__) == ["InMemoryAuditSink", "InMemoryQueue"]
    assert InMemoryQueue.__module__ == "teecustody_sim.backends.memory"
    assert InMemoryAuditSink.__module__ == "teecustody_sim.backends.memory"


def test_sim_package_root_is_unchanged() -> None:
    for name in ("InMemoryQueue", "InMemoryAuditSink", "generate_channel_suite", "backends"):
        assert name not in teecustody_sim.__all__


class _InMemoryQueueSpec:
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
    ) -> None: ...
    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None: ...
    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]: ...
    def ack(self, message_id: str) -> None: ...
    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None: ...
    def withdraw_bundle(self, instance_id: str) -> None: ...
    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]: ...
    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str: ...
    def pull_responses(
        self, client_id: str, after: str | None, max_messages: int
    ) -> ResponsePage: ...


class _InMemoryAuditSinkSpec:
    def __init__(self) -> None: ...
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult: ...
    def records(
        self, record_class: AuditClass | None = None
    ) -> list[tuple[AuditKey, AuditRecord]]: ...
    def fail_next(self, n: int, code: AuditErrorCode = AuditErrorCode.UNAVAILABLE) -> None: ...


def _spec_generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path: ...


QUEUE_METHODS = (
    "__init__",
    "publish_bundle",
    "pull_requests",
    "ack",
    "publish_response",
    "withdraw_bundle",
    "list_bundles",
    "publish_request",
    "pull_responses",
)
SINK_METHODS = ("__init__", "append", "records", "fail_next")

FROZEN_SIGNATURES: dict[str, tuple[object, object]] = {
    **{
        f"InMemoryQueue.{n}": (getattr(InMemoryQueue, n), getattr(_InMemoryQueueSpec, n))
        for n in QUEUE_METHODS
    },
    **{
        f"InMemoryAuditSink.{n}": (
            getattr(InMemoryAuditSink, n),
            getattr(_InMemoryAuditSinkSpec, n),
        )
        for n in SINK_METHODS
    },
    "generate_channel_suite": (generate_channel_suite, _spec_generate_channel_suite),
}


@pytest.mark.parametrize(
    ("actual", "spec"), FROZEN_SIGNATURES.values(), ids=FROZEN_SIGNATURES.keys()
)
def test_full_signature_equals_api_transcription(actual: object, spec: object) -> None:
    assert callable(actual)
    assert callable(spec)
    assert inspect.signature(actual, eval_str=True) == inspect.signature(spec, eval_str=True)


def test_in_memory_queue_has_every_queue_port_method() -> None:
    port_methods = {
        name
        for base in Queue.__mro__
        for name, value in vars(base).items()
        if callable(value) and not name.startswith("_")
    }
    assert port_methods == set(QUEUE_METHODS) - {"__init__"}
