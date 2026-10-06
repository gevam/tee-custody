"""Contract: Reference Gateway HTTP routes over the in-memory relay queue (FR-5, SR-1, SR-3, SR-4;
INC-2-API §6; D-003, D2-13).

Expected red until T-14 and T-24 merge (docs/tasks/INC-2/WAVES.md).
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi.testclient import TestClient
from notes_gateway import GatewayLimits, create_app
from tc_channel_support import FakeClock

from teecustody_sim.backends import InMemoryQueue

INSTANCE = "a1" * 16
CLIENT = "c1" * 16
SECURITY_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


def _client(queue: InMemoryQueue, **limits: Any) -> TestClient:
    return TestClient(create_app(queue, limits=GatewayLimits(**limits)))


def _assert_security_headers(raw: Any) -> None:
    headers = {name.lower(): value for name, value in raw.items()}
    for name, value in SECURITY_HEADERS.items():
        assert headers[name] == value
    assert not any(name.lower().startswith("access-control-") for name in headers)


def test_bundles_are_relayed_as_unpadded_base64url() -> None:
    clock = FakeClock()
    queue = InMemoryQueue(clock=clock)
    queue.publish_bundle(INSTANCE, b"\xfb\xff", int(clock()) + 60)

    response = _client(queue).get("/bundles")

    assert response.status_code == 200
    assert response.json() == {"bundles": [{"instance_id": INSTANCE, "bundle": "-_8"}]}
    _assert_security_headers(response.headers)


def test_request_is_relayed_with_a_minted_relay_id() -> None:
    clock = FakeClock()
    queue = InMemoryQueue(clock=clock)
    queue.publish_bundle(INSTANCE, b"b", int(clock()) + 60)

    response = _client(queue).post(
        f"/requests/{INSTANCE}",
        content=b"\x01\x02",
        headers={"Content-Type": "application/octet-stream"},
    )

    assert response.status_code == 202
    relay_id = response.json()["request_id"]
    [message] = queue.pull_requests(INSTANCE, 1, 0.0)
    assert (message.request_id, message.body) == (relay_id, b"\x01\x02")


def test_unknown_instance_is_404_and_unknown_client_is_an_empty_page() -> None:
    client = _client(InMemoryQueue())

    posted = client.post(
        f"/requests/{INSTANCE}", content=b"x", headers={"Content-Type": "application/octet-stream"}
    )
    page = client.get(f"/responses/{CLIENT}")

    assert (posted.status_code, posted.json()) == (404, {"code": "UNKNOWN_INSTANCE"})
    assert (page.status_code, page.json()) == (200, {"responses": [], "next": None})


def test_responses_are_paged_with_cursors() -> None:
    queue = InMemoryQueue()
    queue.publish_response(CLIENT, "0" * 32, b"\x00")
    client = _client(queue, max_page=1)

    first = client.get(f"/responses/{CLIENT}").json()

    assert first["responses"] == [
        {"request_id": "0" * 32, "body": base64.urlsafe_b64encode(b"\x00").decode().rstrip("=")}
    ]
    assert client.get(f"/responses/{CLIENT}", params={"after": first["next"]}).json() == {
        "responses": [],
        "next": None,
    }


def test_malformed_routes_are_rejected_without_a_queue_call() -> None:
    client = _client(InMemoryQueue())
    for path in (
        f"/responses/{CLIENT}%0A",
        f"/responses/{CLIENT.upper()}",
        f"/responses/{CLIENT[:-1]}",
        f"/responses/{CLIENT}a",
    ):
        response = client.get(path)
        assert (response.status_code, response.json()) == (400, {"code": "INVALID_ARGUMENT"})


def test_rate_limit_answers_429_with_retry_after() -> None:
    client = _client(InMemoryQueue(), per_source_rate=0.001, per_source_burst=1)

    assert client.get("/bundles").status_code == 200
    limited = client.get("/bundles")

    assert (limited.status_code, limited.json()) == (429, {"code": "RATE_LIMITED"})
    assert int(limited.headers["retry-after"]) >= 1
