"""QA exploratory (INC-2 phase 2): gateway per-source keying (IPv6 /64, mapped IPv4, unknown) and CORS defaults.

In-process (Starlette TestClient with a chosen ASGI peer address); a frozen clock means no refill.
"""

import pytest
from fastapi.testclient import TestClient
from notes_gateway import GatewayLimits, create_app

from teecustody_sim.backends import InMemoryQueue

BURST = 3


def _client(peer: str | None, **kw: object) -> TestClient:
    limits = GatewayLimits(per_source_burst=BURST, **kw)  # type: ignore[arg-type]
    app = create_app(InMemoryQueue(), limits=limits, clock=lambda: 1000.0)
    return TestClient(app, client=(peer, 5000) if peer is not None else None)  # type: ignore[arg-type]


def _exhaust(c: TestClient) -> list[int]:
    return [c.get("/bundles").status_code for _ in range(BURST + 2)]


def _share_app(peer_a: str, peer_b: str) -> tuple[list[int], list[int]]:
    limits = GatewayLimits(per_source_burst=BURST)
    app = create_app(InMemoryQueue(), limits=limits, clock=lambda: 1000.0)
    a = TestClient(app, client=(peer_a, 1))
    b = TestClient(app, client=(peer_b, 2))
    return _exhaust(a), [b.get("/bundles").status_code for _ in range(2)]


def test_same_ipv6_slash64_shares_one_bucket() -> None:
    a, b = _share_app("2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff")
    assert a[:BURST] == [200] * BURST and a[BURST:] == [429, 429]
    assert b == [429, 429]


def test_different_ipv6_slash64_has_its_own_bucket() -> None:
    _a, b = _share_app("2001:db8:1:2::1", "2001:db8:1:3::1")
    assert b == [200, 200]


def test_ipv4_mapped_ipv6_shares_the_ipv4_bucket() -> None:
    a, b = _share_app("203.0.113.7", "::ffff:203.0.113.7")
    assert a[BURST] == 429 and b == [429, 429]


def test_ipv4_addresses_are_not_merged_by_prefix() -> None:
    _a, b = _share_app("203.0.113.7", "203.0.113.8")
    assert b == [200, 200]


@pytest.mark.parametrize(
    "peer", ["not-an-ip", "", "2001:db8::1%eth0", "999.1.1.1", "::ffff:999.1.1.1"]
)
def test_unparseable_peers_share_the_unknown_key_and_do_not_crash(peer: str) -> None:
    codes = _exhaust(_client(peer))
    assert codes[:BURST] == [200] * BURST and codes[BURST:] == [429, 429]


def test_missing_peer_does_not_crash() -> None:
    limits = GatewayLimits(per_source_burst=BURST)
    app = create_app(InMemoryQueue(), limits=limits, clock=lambda: 1000.0)
    sent = []

    async def run() -> None:
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/bundles",
            "raw_path": b"/bundles",
            "query_string": b"",
            "headers": [],
            "http_version": "1.1",
            "scheme": "http",
            "server": ("x", 80),
            "client": None,
            "root_path": "",
        }

        async def receive() -> dict[str, object]:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        await app(scope, receive, send)  # type: ignore[arg-type]

    import asyncio

    asyncio.run(run())
    assert sent[0]["status"] == 200


def test_default_limits_send_no_cors_headers_at_all() -> None:
    c = _client("203.0.113.1")
    for origin in ("http://127.0.0.1:5173", "null", "https://evil.test"):
        r = c.get("/bundles", headers={"Origin": origin})
        assert not [h for h in r.headers if h.lower().startswith("access-control")]
        assert "origin" not in r.headers.get("vary", "").lower()
    r = c.options(
        "/bundles", headers={"Origin": "https://evil.test", "Access-Control-Request-Method": "GET"}
    )
    assert not [h for h in r.headers if h.lower().startswith("access-control")]


@pytest.mark.parametrize(
    "bad",
    [
        "*",
        "http://evil.test",
        "https://a.test/",
        "https://a.test/x",
        "ftp://a",
        "https://",
        "https://a.test?x",
        "https://user@a.test",
        "null",
        "",
        "http://localhost.evil.test",
    ],
)
def test_invalid_cors_origins_are_refused_at_startup(bad: str) -> None:
    with pytest.raises(ValueError, match="INVALID_CORS_ORIGIN"):
        create_app(InMemoryQueue(), limits=GatewayLimits(cors_origins=(bad,)))


@pytest.mark.parametrize(
    "kw",
    [
        {"per_source_max_in_flight": 0},
        {"per_source_max_in_flight": 65},
        {"per_source_max_in_flight": True},
        {"body_read_timeout_s": 0.5},
        {"body_read_timeout_s": 61},
        {"body_read_timeout_s": float("nan")},
        {"body_read_timeout_s": float("inf")},
        {"body_read_timeout_s": "10"},
    ],
)
def test_hardening_limits_are_validated(kw: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="INVALID_LIMITS"):
        create_app(InMemoryQueue(), limits=GatewayLimits(**kw))  # type: ignore[arg-type]
