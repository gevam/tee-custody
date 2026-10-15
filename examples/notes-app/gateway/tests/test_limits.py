"""T-14: gateway budgets and resource limits (INC-2-API §6; SR-4; API-TL TL-4)."""

from __future__ import annotations

import asyncio
import logging
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


async def _drive(
    app: ASGIApp,
    path: str,
    client: tuple[str, int] | None,
    *,
    method: str = "GET",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: list[bytes] | None = None,
    gap_s: float = 0.0,
) -> Exchange:
    """One raw ASGI exchange. With `body`, each chunk arrives `gap_s` after the previous one
    and the client then stalls without ever finishing the body."""
    sent: list[Message] = []
    pending = list(body) if body is not None else None

    async def receive() -> Message:
        if pending is None:
            return {"type": "http.request", "body": b"", "more_body": False}
        if pending:
            await asyncio.sleep(gap_s)
            return {"type": "http.request", "body": pending.pop(0), "more_body": True}
        await asyncio.Event().wait()  # the client stalls until the gateway gives up
        raise AssertionError  # pragma: no cover

    async def send(message: Message) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
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


# ---------------------------------------------------------------- criterion 10: TL-4 numeric limits
INT_FIELDS = [
    "max_request_bytes",
    "max_bundles",
    "max_page",
    "per_source_burst",
    "global_burst",
    "max_concurrency",
    "max_sources_tracked",
]
FLOAT_FIELDS = ["per_source_rate", "global_rate"]


@pytest.mark.parametrize("field", INT_FIELDS)
@pytest.mark.parametrize("value", [0, -1, True, 1.0, "1", None], ids=repr)
def test_an_int_limit_that_is_not_a_positive_int_is_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_LIMITS$"):
        create_app(CountingRelay(), limits=GatewayLimits(**{field: value}))  # type: ignore[arg-type]


@pytest.mark.parametrize("field", FLOAT_FIELDS)
@pytest.mark.parametrize(
    "value",
    [0.0, -0.5, 0, float("nan"), float("inf"), True, "1.0", None],
    ids=repr,
)
def test_a_rate_that_is_not_finite_and_positive_is_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_LIMITS$"):
        create_app(CountingRelay(), limits=GatewayLimits(**{field: value}))  # type: ignore[arg-type]


@pytest.mark.parametrize("field", FLOAT_FIELDS)
@pytest.mark.parametrize("value", [1, 0.001, 1e9], ids=repr)
def test_a_finite_positive_int_or_float_rate_is_accepted(field: str, value: float) -> None:
    app = create_app(CountingRelay(), limits=GatewayLimits(**{field: value}))

    assert TestClient(app).get("/bundles").status_code == 200


def test_limits_are_checked_before_cors_origins() -> None:
    limits = GatewayLimits(max_page=0, cors_origins=("*",))

    with pytest.raises(ValueError, match=r"^INVALID_LIMITS$"):
        create_app(CountingRelay(), limits=limits)


# ---------------------------------------------------------------- criterion 12: A1 check order
def test_per_source_in_flight_cap_answers_429_retry_after_one_and_spares_other_sources() -> None:
    relay, clock = CountingRelay(block=True), Clock()
    app = _app(relay, clock, per_source_max_in_flight=2)
    peer, other = ("192.0.2.1", 40000), ("192.0.2.2", 40000)

    async def scenario() -> tuple[list[Exchange], Exchange, Exchange, Exchange]:
        held = [asyncio.create_task(_drive(app, "/bundles", peer)) for _ in range(2)]
        await _until(lambda: relay.entered == 2)
        excess = await _drive(app, "/bundles", peer)
        served = await _drive(app, f"/responses/{'c3' * 16}", other)
        relay.release.set()
        finished = list(await asyncio.gather(*held))
        again = await _drive(app, "/bundles", peer)
        return finished, excess, served, again

    finished, excess, served, again = asyncio.run(scenario())

    assert (excess.status, excess.body, excess.headers["retry-after"]) == (429, RATE_LIMITED, "1")
    assert served.status == 200
    assert [r.status for r in finished] == [200, 200]
    assert again.status == 200
    assert relay.calls == 4


def test_a_request_refused_for_concurrency_spends_no_token() -> None:
    relay, clock = CountingRelay(block=True), Clock()
    app = _app(relay, clock, max_concurrency=1, per_source_max_in_flight=1, per_source_burst=2)
    peer = ("192.0.2.1", 40000)

    async def scenario() -> tuple[Exchange, Exchange, Exchange]:
        held = asyncio.create_task(_drive(app, "/bundles", peer))
        await _until(lambda: relay.entered == 1)
        refused = await _drive(app, "/bundles", peer)
        relay.release.set()
        first = await held
        return first, refused, await _drive(app, "/bundles", peer)

    first, refused, last = asyncio.run(scenario())

    assert (first.status, refused.status, last.status) == (200, 429, 200)


def test_a_request_refused_by_a_bucket_releases_both_slots() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(
        relay,
        clock,
        max_concurrency=1,
        per_source_max_in_flight=1,
        per_source_rate=0.25,
        per_source_burst=1,
    )
    client = _source(app, "192.0.2.1")
    assert client.get("/bundles").status_code == 200

    limited = client.get("/bundles")
    clock.now += 4.0

    assert (limited.status_code, limited.headers["retry-after"]) == (429, "4")
    assert client.get("/bundles").status_code == 200


# ---------------------------------------------------------------- criterion 13: A1 body deadline
REQUEST_TIMEOUT = b'{"code":"REQUEST_TIMEOUT"}'


def _declared(length: int) -> list[tuple[bytes, bytes]]:
    return [
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(length).encode()),
    ]


def _stack_built(app: ASGIApp) -> bool:
    """True once the app has built its middleware stack (on its first request)."""
    return typing.cast("typing.Any", app).middleware_stack is not None


def _guard_of(app: ASGIApp) -> typing.Any:
    """The gateway's outer ASGI layer, found by walking the built middleware stack."""
    layer: typing.Any = typing.cast("typing.Any", app).middleware_stack
    while not hasattr(layer, "_in_flight_by_source"):
        layer = layer.app
    return layer


def test_slow_body_drips_are_capped_per_source_and_answered_408_at_the_deadline() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, body_read_timeout_s=1.0)
    dripper, other = ("192.0.2.1", 40000), ("192.0.2.2", 40000)

    async def scenario() -> tuple[list[Exchange], Exchange, int]:
        drips = [
            asyncio.create_task(
                _drive(
                    app,
                    f"/requests/{INSTANCE}",
                    dripper,
                    method="POST",
                    headers=_declared(65536),
                    body=[b"x"],
                )
            )
            for _ in range(64)
        ]
        await _until(lambda: sum(t.done() for t in drips) == 56)
        served = await _drive(app, "/bundles", other)
        still_held = sum(not t.done() for t in drips)
        return list(await asyncio.gather(*drips)), served, still_held

    drips, served, still_held = asyncio.run(asyncio.wait_for(scenario(), 15))

    assert (served.status, still_held) == (200, 8)
    refused = [d for d in drips if d.status == 429]
    timed_out = [d for d in drips if d.status == 408]
    assert (len(refused), len(timed_out)) == (56, 8)
    assert all(d.headers["retry-after"] == "1" for d in refused)
    for d in timed_out:
        assert d.body == REQUEST_TIMEOUT
        assert d.headers["connection"] == "close"
        assert d.headers["content-type"] == "application/json"
    assert relay.calls == 1  # only the second source's GET /bundles reached the queue
    guard = _guard_of(app)
    assert (guard._in_flight, guard._in_flight_by_source) == (0, {})


def test_the_body_deadline_is_total_not_per_chunk(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="teecustody")
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, body_read_timeout_s=1.0)

    async def scenario() -> Exchange:
        return await _drive(
            app,
            f"/requests/{INSTANCE}",
            ("192.0.2.1", 40000),
            method="POST",
            headers=_declared(10),
            body=[b"a", b"b", b"c", b"d"],
            gap_s=0.4,
        )

    logging.getLogger("teecustody").addHandler(caplog.handler)
    try:
        result = asyncio.run(asyncio.wait_for(scenario(), 15))
    finally:
        logging.getLogger("teecustody").removeHandler(caplog.handler)

    assert (result.status, result.body) == (408, REQUEST_TIMEOUT)
    assert relay.calls == 0
    assert [r.getMessage() for r in caplog.records] == ["GATEWAY_REQUEST_TIMEOUT"]


# ---------------------------------------------------------------- criterion 14: slot release
def test_a_cancelled_request_releases_its_slots() -> None:
    relay, clock = CountingRelay(), Clock()
    app = _app(relay, clock, max_concurrency=1, per_source_max_in_flight=1)
    peer = ("192.0.2.1", 40000)

    async def scenario() -> Exchange:
        stalled = asyncio.create_task(
            _drive(
                app,
                f"/requests/{INSTANCE}",
                peer,
                method="POST",
                headers=_declared(10),
                body=[b"x"],
            )
        )
        await _until(lambda: _stack_built(app) and _guard_of(app)._in_flight == 1)
        stalled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await stalled
        return await _drive(app, "/bundles", peer)

    after = asyncio.run(asyncio.wait_for(scenario(), 15))

    assert after.status == 200
    guard = _guard_of(app)
    assert (guard._in_flight, guard._in_flight_by_source) == (0, {})
