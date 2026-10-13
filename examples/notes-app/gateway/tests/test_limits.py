"""T-14: gateway budgets and resource limits (INC-2-API §6; SR-4; API-TL TL-4)."""

from __future__ import annotations

import asyncio
import threading
import typing
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from starlette.types import ASGIApp

from notes_gateway import GatewayLimits, create_app
from teecustody.queue import PublishedBundle, ResponsePage

INSTANCE = "a1" * 16
RATE_LIMITED = b'{"code":"RATE_LIMITED"}'
Message = dict[str, object]


class Clock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class CountingRelay:
    """A RelayQueue fake that counts calls; `list_bundles` can block until released."""

    def __init__(self, *, block: bool = False) -> None:
        self.calls = 0
        self.entered = 0
        self.release = threading.Event()
        if not block:
            self.release.set()

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        self.calls += 1
        self.entered += 1
        self.release.wait(timeout=10)
        return []

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.calls += 1
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        self.calls += 1
        return ResponsePage((), None)


def _source(app: ASGIApp, host: str) -> TestClient:
    return TestClient(app, client=(host, 40000))


def _app(relay: CountingRelay, clock: Clock, **limits: typing.Any) -> ASGIApp:
    return create_app(relay, limits=GatewayLimits(**limits), clock=clock)


# ---------------------------------------------------------------- criterion 7: SR-4 budgets
def test_per_source_budget_answers_429_with_retry_after_before_any_queue_call() -> None:
    relay, clock = CountingRelay(), Clock()
    client = _source(_app(relay, clock, per_source_rate=1.0, per_source_burst=2), "192.0.2.1")

    codes = [client.get("/bundles").status_code for _ in range(2)]
    limited = client.get("/bundles")

    assert codes == [200, 200]
    assert (limited.status_code, limited.content) == (429, RATE_LIMITED)
    assert limited.headers["content-type"] == "application/json"
    assert limited.headers["retry-after"] == "1"
    assert relay.calls == 2


@pytest.mark.parametrize(
    ("rate", "elapsed", "retry_after"),
    [(0.25, 0.0, "4"), (0.3, 0.0, "4"), (1.0, 0.5, "1"), (0.5, 0.5, "2"), (0.001, 0.0, "1000")],
)
def test_retry_after_is_the_ceiling_of_seconds_until_one_token(
    rate: float, elapsed: float, retry_after: str
) -> None:
    relay, clock = CountingRelay(), Clock()
    client = _source(_app(relay, clock, per_source_rate=rate, per_source_burst=1), "192.0.2.1")
    assert client.get("/bundles").status_code == 200
    clock.now += elapsed

    limited = client.get("/bundles")

    assert (limited.status_code, limited.headers["retry-after"]) == (429, retry_after)


def test_refill_restores_service_at_rate_and_never_beyond_burst() -> None:
    relay, clock = CountingRelay(), Clock()
    client = _source(_app(relay, clock, per_source_rate=2.0, per_source_burst=3), "192.0.2.1")
    assert [client.get("/bundles").status_code for _ in range(4)] == [200, 200, 200, 429]

    clock.now += 0.5
    assert [client.get("/bundles").status_code for _ in range(2)] == [200, 429]

    clock.now += 1000.0
    assert [client.get("/bundles").status_code for _ in range(4)] == [200, 200, 200, 429]


def test_an_in_budget_second_source_is_served_while_the_first_is_limited() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, per_source_rate=1.0, per_source_burst=1, global_burst=2)
    first, second = _source(app, "192.0.2.1"), _source(app, "192.0.2.2")

    assert first.get("/bundles").status_code == 200
    assert [first.get("/bundles").status_code for _ in range(5)] == [429] * 5
    assert second.get("/bundles").status_code == 200
    assert relay.calls == 2


def test_global_budget_answers_429_for_every_source_before_any_queue_call() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, global_rate=0.5, global_burst=2)
    sources = [_source(app, f"192.0.2.{i}") for i in range(3)]

    codes = [s.get("/bundles").status_code for s in sources[:2]]
    limited = sources[2].get("/bundles")

    assert codes == [200, 200]
    assert (limited.status_code, limited.content) == (429, RATE_LIMITED)
    assert limited.headers["retry-after"] == "2"
    assert relay.calls == 2
    clock.now += 2.0
    assert sources[2].get("/bundles").status_code == 200


def test_global_bucket_is_checked_before_the_per_source_bucket() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(
        relay, clock, per_source_rate=1.0, per_source_burst=1, global_rate=0.25, global_burst=1
    )
    client = _source(app, "192.0.2.1")
    assert client.get("/bundles").status_code == 200

    limited = client.get("/bundles")

    assert (limited.status_code, limited.headers["retry-after"]) == (429, "4")


def test_a_globally_refused_request_does_not_spend_its_source_budget() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(
        relay, clock, per_source_rate=0.001, per_source_burst=1, global_rate=1.0, global_burst=1
    )
    first, second = _source(app, "192.0.2.1"), _source(app, "192.0.2.2")
    assert first.get("/bundles").status_code == 200
    assert second.get("/bundles").status_code == 429

    clock.now += 1.0

    assert second.get("/bundles").status_code == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/nothing"), ("GET", f"/responses/{'A' * 32}"), ("POST", f"/requests/{INSTANCE}")],
)
def test_every_request_spends_budget_whatever_its_route_or_validity(method: str, path: str) -> None:
    relay, clock = CountingRelay(), Clock()
    client = _source(_app(relay, clock, per_source_rate=1.0, per_source_burst=1), "192.0.2.1")
    client.request(method, path, content=b"", headers={"Content-Type": "text/plain"})

    limited = client.get("/bundles")

    assert (limited.status_code, limited.content) == (429, RATE_LIMITED)
    assert relay.calls == 0


# ---------------------------------------------------------------- raw ASGI driver
@dataclass
class Exchange:
    status: int
    headers: dict[str, str]
    body: bytes


async def _drive(app: ASGIApp, path: str, client: tuple[str, int] | None) -> Exchange:
    sent: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [],
        "client": client,
        "server": ("testserver", 80),
    }
    await app(scope, receive, send)  # type: ignore[arg-type]
    start, *rest = sent
    raw_headers = typing.cast("list[tuple[bytes, bytes]]", start["headers"])
    return Exchange(
        status=typing.cast("int", start["status"]),
        headers={k.decode().lower(): v.decode() for k, v in raw_headers},
        body=b"".join(typing.cast("bytes", m.get("body", b"")) for m in rest),
    )


async def _until(condition: typing.Callable[[], bool]) -> None:
    for _ in range(1000):
        if condition():
            return
        await asyncio.sleep(0.005)
    raise AssertionError("condition not reached")  # pragma: no cover


def test_requests_beyond_max_concurrency_are_429_with_retry_after_one() -> None:
    relay, clock = CountingRelay(block=True), Clock()
    app = _app(relay, clock, max_concurrency=2)
    peer = ("192.0.2.1", 40000)

    async def scenario() -> tuple[list[Exchange], Exchange, Exchange]:
        held = [asyncio.create_task(_drive(app, "/bundles", peer)) for _ in range(2)]
        await _until(lambda: relay.entered == 2)
        excess = await _drive(app, "/bundles", peer)
        relay.release.set()
        finished = list(await asyncio.gather(*held))
        after = await _drive(app, "/bundles", peer)
        return finished, excess, after

    finished, excess, after = asyncio.run(scenario())

    assert (excess.status, excess.body, excess.headers["retry-after"]) == (429, RATE_LIMITED, "1")
    assert [r.status for r in finished] == [200, 200]
    assert after.status == 200
    assert relay.calls == 3


def test_a_failing_request_releases_its_concurrency_slot() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, max_concurrency=1)
    client = TestClient(app, raise_server_exceptions=False)

    assert client.get("/nothing").status_code == 404
    assert client.post(f"/requests/{INSTANCE}", content=b"").status_code == 400
    assert client.get("/bundles").status_code == 200


def test_a_peer_without_an_address_is_budgeted_as_one_unknown_source() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, per_source_rate=1.0, per_source_burst=1)

    async def scenario() -> list[Exchange]:
        return [await _drive(app, "/bundles", None) for _ in range(2)]

    first, second = asyncio.run(scenario())

    assert (first.status, second.status) == (200, 429)
    assert _source(app, "unknown").get("/bundles").status_code == 429
    assert _source(app, "192.0.2.9").get("/bundles").status_code == 200


def test_forwarded_headers_are_never_trusted_for_the_source() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, per_source_rate=1.0, per_source_burst=1)
    client = _source(app, "192.0.2.1")
    assert client.get("/bundles").status_code == 200

    spoofed = client.get(
        "/bundles", headers={"X-Forwarded-For": "203.0.113.5", "X-Real-IP": "203.0.113.6"}
    )

    assert spoofed.status_code == 429


def test_lifespan_events_pass_through_without_spending_budget() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, per_source_rate=1.0, per_source_burst=1, global_burst=1)

    with TestClient(app, client=("unknown", 40000)) as client:
        assert client.get("/bundles").status_code == 200


# ------------------------------------------------------------- criterion 8: LRU of source buckets
def test_the_least_recently_used_source_bucket_is_evicted() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, per_source_rate=0.001, per_source_burst=1, max_sources_tracked=2)
    a, b, c = (_source(app, f"192.0.2.{i}") for i in (1, 2, 3))

    assert [a.get("/bundles").status_code, b.get("/bundles").status_code] == [200, 200]
    assert a.get("/bundles").status_code == 429  # A is now the most recently used
    assert c.get("/bundles").status_code == 200  # tracking C evicts B, not A
    assert b.get("/bundles").status_code == 200  # B starts a fresh bucket; A is evicted
    assert c.get("/bundles").status_code == 429  # C is still tracked
    assert a.get("/bundles").status_code == 200  # A was evicted
