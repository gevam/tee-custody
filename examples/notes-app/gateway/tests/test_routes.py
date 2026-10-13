"""T-14: the reference gateway routes (INC-2-API §6; FR-5, SR-1, SR-3/R-7, SR-11; D-003, D2-13)."""

from __future__ import annotations

import json

import pytest
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


# ---------------------------------------------------------------- criterion 2: POST /requests
OCTET = {"Content-Type": "application/octet-stream"}


def test_request_is_relayed_unchanged_with_the_relay_id_from_rng() -> None:
    relay = RecordingRelay()
    sizes: list[int] = []

    def rng(n: int) -> bytes:
        sizes.append(n)
        return bytes(range(n))

    client = TestClient(create_app(relay, rng=rng))
    body = bytes(range(256)) * 3

    response = client.post(f"/requests/{INSTANCE}", content=body, headers=OCTET)

    assert response.status_code == 202
    assert response.headers["content-type"] == "application/json"
    assert response.content == b'{"request_id":"' + bytes(range(16)).hex().encode() + b'"}'
    assert sizes == [16]
    assert relay.calls == [("publish_request", INSTANCE, bytes(range(16)).hex(), body)]


# ---------------------------------------------------------------- criterion 3: R-7 route syntax
CLIENT = "c3" * 16
BAD_IDS = [
    pytest.param(INSTANCE + "%0A", id="trailing-newline"),
    pytest.param("%0A" + INSTANCE[1:], id="leading-newline"),
    pytest.param(INSTANCE.upper(), id="uppercase"),
    pytest.param(INSTANCE[:-1], id="31-chars"),
    pytest.param(INSTANCE + "a", id="33-chars"),
    pytest.param("g" * 32, id="non-hex"),
]
INVALID = b'{"code":"INVALID_ARGUMENT"}'


@pytest.mark.parametrize("bad", BAD_IDS)
def test_malformed_instance_is_400_with_no_queue_call(bad: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).post(f"/requests/{bad}", content=b"x", headers=OCTET)

    assert (response.status_code, response.content) == (400, INVALID)
    assert response.headers["content-type"] == "application/json"
    assert relay.calls == []


@pytest.mark.parametrize("bad", BAD_IDS)
def test_malformed_client_is_400_with_no_queue_call(bad: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).get(f"/responses/{bad}")

    assert (response.status_code, response.content) == (400, INVALID)
    assert relay.calls == []


@pytest.mark.parametrize(
    "query",
    [
        pytest.param("after=", id="empty"),
        pytest.param("after=" + "a" * 129, id="129-chars"),
        pytest.param("after=bad%20cursor", id="space"),
        pytest.param("after=abc%0A", id="trailing-newline"),
        pytest.param("after=%0Aabc", id="leading-newline"),
        pytest.param("after=abc%2B", id="plus"),
        pytest.param("after=abc=", id="padding"),
    ],
)
def test_malformed_cursor_is_400_with_no_queue_call(query: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).get(f"/responses/{CLIENT}?{query}")

    assert (response.status_code, response.content) == (400, INVALID)
    assert relay.calls == []


@pytest.mark.parametrize("cursor", ["a", "A-z_09", "x" * 128])
def test_well_formed_cursor_reaches_the_queue_unchanged(cursor: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).get(f"/responses/{CLIENT}", params={"after": cursor})

    assert response.status_code == 200
    assert relay.calls == [("pull_responses", CLIENT, cursor, 32)]


def test_responses_are_paged_as_compact_json_with_unpadded_base64url() -> None:
    relay = RecordingRelay()
    relay.pages[CLIENT] = ResponsePage(
        (PublishedResponse("aa" * 16, b"\xfb\xff"), PublishedResponse("bb" * 16, b"b")), "cur-1"
    )

    response = _client(relay).get(f"/responses/{CLIENT}")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.content == (
        b'{"responses":[{"request_id":"' + b"aa" * 16 + b'","body":"-_8"},'
        b'{"request_id":"' + b"bb" * 16 + b'","body":"Yg"}],"next":"cur-1"}'
    )
    assert relay.calls == [("pull_responses", CLIENT, None, 32)]


def test_responses_never_exceed_max_page_even_if_the_queue_returns_more() -> None:
    relay = RecordingRelay()
    relay.pages[CLIENT] = ResponsePage(
        tuple(PublishedResponse(f"{i:032x}", b"b") for i in range(3)), None
    )

    response = _client(relay, GatewayLimits(max_page=2)).get(f"/responses/{CLIENT}")

    assert [r["request_id"] for r in json.loads(response.content)["responses"]] == [
        f"{i:032x}" for i in range(2)
    ]
    assert relay.calls == [("pull_responses", CLIENT, None, 2)]
