"""T-14: gateway CORS policy (INC-2-API §6 security note (c); API-TL TL-4)."""

from __future__ import annotations

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient

from notes_gateway import GatewayLimits, create_app
from teecustody.queue import PublishedBundle, ResponsePage

INSTANCE = "a1" * 16
APP_ORIGIN = "https://app.example"
OCTET = {"Content-Type": "application/octet-stream"}


class StaticRelay:
    """A RelayQueue fake with fixed answers."""

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        return []

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        return ResponsePage((), None)


def _client(*origins: str, **limits: object) -> TestClient:
    app = create_app(StaticRelay(), limits=GatewayLimits(cors_origins=origins, **limits))  # type: ignore[arg-type]
    return TestClient(app)


def _cors_headers(response: httpx.Response) -> dict[str, str]:
    return {k: v for k, v in response.headers.items() if k.lower().startswith("access-control-")}


def _exchanges(client: TestClient, origin: str) -> list[httpx.Response]:
    """One of every response kind the gateway produces, each sent with `origin`."""
    with_origin = {"Origin": origin}
    preflight = {**with_origin, "Access-Control-Request-Method": "POST"}
    return [
        client.get("/bundles", headers=with_origin),
        client.post(f"/requests/{INSTANCE}", content=b"x", headers={**OCTET, **with_origin}),
        client.post(f"/requests/{INSTANCE}", content=b"", headers={**OCTET, **with_origin}),
        client.get("/nothing", headers=with_origin),
        client.options(f"/requests/{INSTANCE}", headers=preflight),
    ]


# ---------------------------------------------------------------- criterion 9: CORS
@pytest.mark.parametrize("origin", [APP_ORIGIN, "https://evil.example", "null"])
def test_default_gateway_sends_no_cors_header_on_any_response(origin: str) -> None:
    for response in _exchanges(_client(), origin):
        assert _cors_headers(response) == {}
        assert "vary" not in response.headers


def test_an_exact_allow_listed_origin_is_echoed_with_vary_and_never_credentials() -> None:
    client = _client("https://other.example", APP_ORIGIN)

    for response in _exchanges(client, APP_ORIGIN)[:4]:
        assert _cors_headers(response) == {"access-control-allow-origin": APP_ORIGIN}
        assert response.headers["vary"] == "Origin"


@pytest.mark.parametrize(
    "origin",
    [
        "https://app.example.evil",
        "https://APP.example",
        "https://app.example:443",
        "https://app.example/",
        "http://app.example",
        "https://app.example ",
        "null",
        "*",
    ],
)
def test_a_non_matching_origin_gets_no_cors_header(origin: str) -> None:
    for response in _exchanges(_client(APP_ORIGIN), origin):
        assert _cors_headers(response) == {}


def test_a_request_with_two_origin_headers_gets_no_cors_header() -> None:
    client = _client(APP_ORIGIN)

    response = client.get("/bundles", headers=[("Origin", APP_ORIGIN), ("Origin", APP_ORIGIN)])

    assert response.status_code == 200
    assert _cors_headers(response) == {}


@pytest.mark.parametrize(
    ("method", "headers"),
    [("POST", "content-type"), ("GET", None), ("DELETE", "x-custom, authorization")],
)
def test_preflight_allows_only_get_post_and_content_type(method: str, headers: str | None) -> None:
    request_headers = {"Origin": APP_ORIGIN, "Access-Control-Request-Method": method}
    if headers is not None:
        request_headers["Access-Control-Request-Headers"] = headers

    response = _client(APP_ORIGIN).options(f"/requests/{INSTANCE}", headers=request_headers)

    assert response.status_code == 200
    assert response.content == b""
    assert _cors_headers(response) == {
        "access-control-allow-origin": APP_ORIGIN,
        "access-control-allow-methods": "GET, POST",
        "access-control-allow-headers": "Content-Type",
    }
    assert response.headers["vary"] == "Origin"


def test_preflight_from_a_non_matching_origin_is_not_answered_as_cors() -> None:
    response = _client(APP_ORIGIN).options(
        "/bundles",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 405
    assert _cors_headers(response) == {}


def test_options_without_request_method_is_not_a_preflight() -> None:
    response = _client(APP_ORIGIN).options("/bundles", headers={"Origin": APP_ORIGIN})

    assert response.status_code == 405
    assert _cors_headers(response) == {"access-control-allow-origin": APP_ORIGIN}


def test_rate_limited_responses_carry_cors_for_a_matching_origin() -> None:
    client = _client(APP_ORIGIN, per_source_burst=1, per_source_rate=0.001)
    client.get("/bundles", headers={"Origin": APP_ORIGIN})

    limited = client.get("/bundles", headers={"Origin": APP_ORIGIN})

    assert limited.status_code == 429
    assert _cors_headers(limited) == {"access-control-allow-origin": APP_ORIGIN}
    assert limited.headers["vary"] == "Origin"


def test_preflight_spends_rate_budget() -> None:
    client = _client(APP_ORIGIN, per_source_burst=1, per_source_rate=0.001)
    preflight = {"Origin": APP_ORIGIN, "Access-Control-Request-Method": "POST"}
    assert client.options(f"/requests/{INSTANCE}", headers=preflight).status_code == 200

    assert client.options(f"/requests/{INSTANCE}", headers=preflight).status_code == 429
