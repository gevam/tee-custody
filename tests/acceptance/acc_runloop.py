"""Run-loop and gateway helpers for INC-2 acceptance tests (QA). Public interfaces only."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from tests.support.channel_doubles import EchoHandler

from acc_channel import (
    CLIENT_ID,
    CS,
    CompositeOpener,
    OpenSent,
    RecordingLogger,
    b64u,
    build_open,
    open_session_payload,
    unb64u,
    uncbor,
)
from acc_support import AUDIENCE, RunningSim
from teecustody.attest import ConfidentialSpaceLauncher, LauncherError, LauncherErrorCode
from teecustody.attest.ports import AttestationToken
from teecustody.config import BoundaryLimits, ChannelParams
from teecustody.queue import (
    PublishedBundle,
    PublishedResponse,
    QueueError,
    QueueErrorCode,
    ResponsePage,
)
from teecustody.runtime import RunLoop
from teecustody_sim.backends import InMemoryAuditSink, InMemoryQueue

IID = "ab" * 16
OCTET = {"Content-Type": "application/octet-stream"}


class SpyRelay:
    """A RelayQueue that records calls and serves canned data (an untrusted-relay stand-in)."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.bundles = [PublishedBundle(IID, b"bundle-bytes")]
        self.requests: list[tuple[str, str, bytes]] = []
        self.responses: dict[str, list[PublishedResponse]] = {}
        self.raise_on_list: Exception | None = None

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        self.calls.append(("list", max_bundles))
        if self.raise_on_list is not None:
            raise self.raise_on_list
        return self.bundles[:max_bundles]

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.calls.append(("post", instance_id, request_id))
        if instance_id != IID:
            raise QueueError(QueueErrorCode.NOT_FOUND)
        self.requests.append((instance_id, request_id, body))
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        self.calls.append(("pull", client_id, after, max_messages))
        items = self.responses.get(client_id, [])
        return ResponsePage(tuple(items[:max_messages]), None)


class FlakyLauncher:
    """Delegates to the simulator launcher; can be switched to fail; counts every call."""

    def __init__(self, inner: ConfidentialSpaceLauncher) -> None:
        self.inner = inner
        self.fail = False
        self.calls = 0

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        self.calls += 1
        if self.fail:
            raise LauncherError(LauncherErrorCode.UNAVAILABLE)
        return self.inner.get_attestation_token(audience, token_type, identity_nonce)


@dataclass
class RunWorld:
    loop: RunLoop
    queue: Any
    sink: InMemoryAuditSink
    opener: CompositeOpener
    handler: EchoHandler
    rs: RunningSim
    launcher: FlakyLauncher
    logger: RecordingLogger
    limits: BoundaryLimits
    used: set[int] = field(default_factory=set)

    @property
    def clock(self) -> Any:
        return self.rs.clock

    def tick(self, n: int = 1) -> Any:
        report = None
        for _ in range(n):
            report = self.loop.tick()
        return report

    def bundle(self) -> dict[str, Any]:
        published = self.queue.list_bundles(16)
        assert [p.instance_id for p in published] == [self.loop.instance_id]
        return uncbor(published[0].bundle)  # type: ignore[no-any-return]

    def open_session(self, *, route: str = CLIENT_ID, cs: bytes = CS, **kw: Any) -> OpenSent:
        bundle = self.bundle()
        entry = next(e for e in bundle["prekeys"] if e["id"] not in self.used)
        self.used.add(entry["id"])
        return build_open(
            ik_pub=bundle["IK_pub"],
            instance_id=bundle["instance_id"],
            prekey=entry,
            route=route,
            payload=open_session_payload(cs),
            timestamp=int(self.clock()),
            **kw,
        )

    def post(self, body: bytes) -> str:
        relay_id: str = self.queue.publish_request(
            self.loop.instance_id, os.urandom(16).hex(), body
        )
        return relay_id

    def responses(self, route: str) -> list[tuple[str, bytes]]:
        page = self.queue.pull_responses(route, None, 32)
        return [(r.request_id, r.body) for r in page.responses]


def make_run_world(
    rs: RunningSim,
    *,
    limits: BoundaryLimits | None = None,
    params: ChannelParams | None = None,
    queue: Any = None,
    opener: CompositeOpener | None = None,
    shares: dict[str, bytes] | None = None,
) -> RunWorld:
    lim = limits if limits is not None else BoundaryLimits(pull_wait_s=0.001)
    prm = params if params is not None else ChannelParams()
    raw = InMemoryQueue(clock=rs.clock)
    q = queue(raw) if callable(queue) else (queue if queue is not None else raw)
    sink = InMemoryAuditSink()
    op = opener if opener is not None else CompositeOpener(shares or {CLIENT_ID: CS})
    handler = EchoHandler()
    launcher = FlakyLauncher(
        ConfidentialSpaceLauncher(
            str(rs.config.socket_path), timeout_s=5.0, max_response_bytes=65536
        )
    )
    logger = RecordingLogger()
    loop = RunLoop(
        launcher=launcher,
        queue=q,
        audit_sink=sink,
        opener=op,
        handler=handler,
        audience=AUDIENCE,
        token_type="OIDC",
        params=prm,
        limits=lim,
        clock=rs.clock,
        logger=logger,
    )
    loop.start()
    return RunWorld(loop, raw, sink, op, handler, rs, launcher, logger, lim)


__all__ = ["FlakyLauncher", "RunWorld", "b64u", "make_run_world", "unb64u"]
