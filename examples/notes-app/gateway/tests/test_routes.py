"""T-14: the reference gateway routes (INC-2-API §6; FR-5, SR-1, SR-3/R-7, SR-11; D-003, D2-13)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from notes_gateway import GatewayLimits, create_app
from teecustody.queue import PublishedBundle, PublishedResponse, ResponsePage

INSTANCE = "a1" * 16
OTHER_INSTANCE = "b2" * 16


class RecordingRelay:
    """A RelayQueue fake that records every call and serves canned data."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.bundles: list[PublishedBundle] = []
        self.pages: dict[str, ResponsePage] = {}
        self.error: Exception | None = None

    def _maybe_raise(self) -> None:
        if self.error is not None:
            raise self.error

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        self.calls.append(("list_bundles", max_bundles))
        self._maybe_raise()
        return list(self.bundles)

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.calls.append(("publish_request", instance_id, request_id, body))
        self._maybe_raise()
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        self.calls.append(("pull_responses", client_id, after, max_messages))
        self._maybe_raise()
        return self.pages.get(client_id, ResponsePage((), None))


def _client(relay: RecordingRelay, limits: GatewayLimits | None = None) -> TestClient:
    return TestClient(create_app(relay, limits=limits or GatewayLimits()))


# ---------------------------------------------------------------- criterion 1: GET /bundles
def test_bundles_are_listed_as_compact_json_with_unpadded_base64url() -> None:
    relay = RecordingRelay()
    relay.bundles = [PublishedBundle(INSTANCE, b"\xfb\xff"), PublishedBundle(OTHER_INSTANCE, b"b")]

    response = _client(relay).get("/bundles")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.content == (
        b'{"bundles":[{"instance_id":"' + INSTANCE.encode() + b'","bundle":"-_8"},'
        b'{"instance_id":"' + OTHER_INSTANCE.encode() + b'","bundle":"Yg"}]}'
    )
    assert relay.calls == [("list_bundles", 16)]


def test_bundles_never_exceed_max_bundles_even_if_the_queue_returns_more() -> None:
    relay = RecordingRelay()
    relay.bundles = [PublishedBundle(f"{i:032x}", b"b") for i in range(3)]

    response = _client(relay, GatewayLimits(max_bundles=2)).get("/bundles")

    assert [b["instance_id"] for b in json.loads(response.content)["bundles"]] == [
        f"{i:032x}" for i in range(2)
    ]
    assert relay.calls == [("list_bundles", 2)]
