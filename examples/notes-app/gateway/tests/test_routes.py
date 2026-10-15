"""T-14: the reference gateway routes (INC-2-API §6; FR-5, SR-1, SR-3/R-7, SR-11; D-003, D2-13)."""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import typing
from collections.abc import Iterator
from dataclasses import dataclass

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient
from starlette.types import ASGIApp

from notes_gateway import GatewayLimits, create_app
from teecustody.queue import (
    PublishedBundle,
    PublishedResponse,
    QueueError,
    QueueErrorCode,
    ResponsePage,
)

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


# ---------------------------------------------------------------- criterion 4: body rules
Message = dict[str, object]


@dataclass
class Exchange:
    status: int
    headers: dict[str, str]
    body: bytes
    receives: int


def _drive(
    app: ASGIApp,
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]],
    messages: list[Message],
    query: bytes = b"",
    client: tuple[str, int] | None = ("198.51.100.7", 40000),
) -> Exchange:
    """Run one HTTP exchange through the raw ASGI interface, feeding `messages` to `receive`."""
    pending = list(messages)
    sent: list[Message] = []
    receives = 0

    async def receive() -> Message:
        nonlocal receives
        receives += 1
        if pending:
            return pending.pop(0)
        await asyncio.Event().wait()  # pragma: no cover - a well-behaved app never gets here
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
        "query_string": query,
        "root_path": "",
        "headers": headers,
        "client": client,
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))  # type: ignore[arg-type]
    start, *rest = sent
    raw_headers = typing.cast("list[tuple[bytes, bytes]]", start["headers"])
    return Exchange(
        status=typing.cast("int", start["status"]),
        headers={k.decode().lower(): v.decode() for k, v in raw_headers},
        body=b"".join(typing.cast("bytes", m.get("body", b"")) for m in rest),
        receives=receives,
    )


def _chunk(data: bytes, more: bool) -> Message:
    return {"type": "http.request", "body": data, "more_body": more}


def _octet(length: int | str) -> list[tuple[bytes, bytes]]:
    return [
        (b"content-type", b"application/octet-stream"),
        (b"content-length", str(length).encode()),
    ]


def test_body_of_exactly_max_request_bytes_is_relayed() -> None:
    relay = RecordingRelay()

    response = _client(relay, GatewayLimits(max_request_bytes=8)).post(
        f"/requests/{INSTANCE}", content=b"12345678", headers=OCTET
    )

    assert response.status_code == 202
    assert relay.calls[0][3] == b"12345678"


@pytest.mark.parametrize(
    ("content", "headers"),
    [
        pytest.param(b"", OCTET, id="empty"),
        pytest.param(b"123456789", OCTET, id="max-plus-one"),
        pytest.param(b"x", {}, id="no-content-type"),
        pytest.param(b"x", {"Content-Type": "application/json"}, id="wrong-type"),
        pytest.param(b"x", {"Content-Type": "application/octet-stream; a=b"}, id="parameterised"),
        pytest.param(b"x", {"Content-Type": "Application/Octet-Stream"}, id="other-case"),
        pytest.param(b"x", {"Content-Type": "application/octet-stream "}, id="trailing-space"),
        pytest.param(iter([b"x"]), OCTET, id="chunked-no-content-length"),
    ],
)
def test_invalid_body_is_400_with_no_queue_call(
    content: bytes | typing.Iterator[bytes], headers: dict[str, str]
) -> None:
    relay = RecordingRelay()

    response = _client(relay, GatewayLimits(max_request_bytes=8)).post(
        f"/requests/{INSTANCE}", content=content, headers=headers
    )

    assert (response.status_code, response.content) == (400, INVALID)
    assert relay.calls == []


@pytest.mark.parametrize(
    "length", ["abc", "-1", "+1", "0x1", "1.0", " 1", "1" * 20, "99999999999999999999999"]
)
def test_malformed_content_length_is_400_without_reading_the_body(length: str) -> None:
    relay = RecordingRelay()
    app = create_app(relay)

    result = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(length), [_chunk(b"x", False)])

    assert (result.status, result.body, result.receives) == (400, INVALID, 0)
    assert relay.calls == []


def test_repeated_content_length_or_content_type_is_400() -> None:
    relay = RecordingRelay()
    app = create_app(relay)
    two_lengths = [*_octet(1), (b"content-length", b"1")]
    two_types = [*_octet(1), (b"content-type", b"application/octet-stream")]

    for headers in (two_lengths, two_types):
        result = _drive(app, "POST", f"/requests/{INSTANCE}", headers, [_chunk(b"x", False)])
        assert (result.status, result.body) == (400, INVALID)
    assert relay.calls == []


def test_declared_length_above_the_limit_is_400_without_reading_the_body() -> None:
    relay = RecordingRelay()
    app = create_app(relay, limits=GatewayLimits(max_request_bytes=8))

    result = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(9), [_chunk(b"x" * 9, False)])

    assert (result.status, result.body, result.receives) == (400, INVALID, 0)
    assert relay.calls == []


def test_body_longer_than_content_length_is_rejected_at_the_first_excess_chunk() -> None:
    relay = RecordingRelay()
    app = create_app(relay, limits=GatewayLimits(max_request_bytes=8))
    chunks = [_chunk(b"ab", True), _chunk(b"cde", True), _chunk(b"f" * 100, False)]

    result = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(4), chunks)

    assert (result.status, result.body, result.receives) == (400, INVALID, 2)
    assert relay.calls == []


def test_body_shorter_than_content_length_is_400() -> None:
    relay = RecordingRelay()
    app = create_app(relay)

    result = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(5), [_chunk(b"abc", False)])

    assert (result.status, result.body) == (400, INVALID)
    assert relay.calls == []


def test_client_disconnect_mid_body_is_400_with_no_queue_call() -> None:
    relay = RecordingRelay()
    app = create_app(relay)

    result = _drive(
        app,
        "POST",
        f"/requests/{INSTANCE}",
        _octet(5),
        [_chunk(b"ab", True), {"type": "http.disconnect"}],
    )

    assert (result.status, result.body) == (400, INVALID)
    assert relay.calls == []


def test_chunked_body_matching_content_length_is_relayed_whole() -> None:
    relay = RecordingRelay()
    app = create_app(relay, rng=lambda n: b"\x00" * n)
    chunks = [_chunk(b"ab", True), _chunk(b"", True), _chunk(b"cde", False)]

    result = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(5), chunks)

    assert result.status == 202
    assert relay.calls == [("publish_request", INSTANCE, "00" * 16, b"abcde")]


# ---------------------------------------------------------------- criterion 5: QueueError mapping
SENTINEL = "SENTINEL-T14-c5e1"


@pytest.fixture
def all_logs(caplog: pytest.LogCaptureFixture) -> Iterator[pytest.LogCaptureFixture]:
    """caplog, also attached to the non-propagating `teecustody` logger tree."""
    base = logging.getLogger("teecustody")
    base.addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="teecustody")
    try:
        yield caplog
    finally:
        base.removeHandler(caplog.handler)


ROUTES = [
    pytest.param(("GET", "/bundles"), id="bundles"),
    pytest.param(("POST", f"/requests/{INSTANCE}"), id="requests"),
    pytest.param(("GET", f"/responses/{CLIENT}"), id="responses"),
]


def _call(client: TestClient, route: tuple[str, str], body: bytes = b"x") -> httpx.Response:
    method, path = route
    if method == "POST":
        return client.post(path, content=body, headers=OCTET)
    return client.get(path)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (QueueError(QueueErrorCode.INVALID_ARGUMENT), 400, "INVALID_ARGUMENT"),
        (QueueError(QueueErrorCode.NOT_FOUND), 404, "UNKNOWN_INSTANCE"),
        (QueueError(QueueErrorCode.UNAVAILABLE), 503, "UNAVAILABLE"),
        (QueueError(QueueErrorCode.CONFLICT), 500, "INTERNAL"),
        (QueueError(QueueErrorCode.INTERNAL), 500, "INTERNAL"),
        (RuntimeError(SENTINEL), 500, "INTERNAL"),
    ],
)
def test_queue_failures_map_to_stable_codes_without_leaking_the_cause(
    route: tuple[str, str],
    error: Exception,
    status: int,
    code: str,
    all_logs: pytest.LogCaptureFixture,
) -> None:
    relay = RecordingRelay()
    relay.error = error
    client = TestClient(create_app(relay), raise_server_exceptions=False)

    response = _call(client, route)

    assert response.status_code == status
    assert response.content == b'{"code":"' + code.encode() + b'"}'
    assert response.headers["content-type"] == "application/json"
    assert SENTINEL not in response.text + all_logs.text
    assert all(record.exc_info is None for record in all_logs.records)


def test_rng_failure_is_500_internal_with_no_queue_call(
    all_logs: pytest.LogCaptureFixture,
) -> None:
    relay = RecordingRelay()

    def broken_rng(n: int) -> bytes:
        raise OSError(SENTINEL)

    client = TestClient(create_app(relay, rng=broken_rng), raise_server_exceptions=False)
    response = client.post(f"/requests/{INSTANCE}", content=b"x", headers=OCTET)

    assert (response.status_code, response.content) == (500, b'{"code":"INTERNAL"}')
    assert relay.calls == []
    assert SENTINEL not in response.text + all_logs.text


# ------------------------------------------------------------ criterion 6: D2-13 no route probing
def test_unknown_client_route_is_an_empty_page_not_an_error() -> None:
    relay = RecordingRelay()

    response = _client(relay).get(f"/responses/{'e' * 32}")

    assert (response.status_code, response.content) == (200, b'{"responses":[],"next":null}')
    assert relay.calls == [("pull_responses", "e" * 32, None, 32)]


# ------------------------------------------------------------- criterion 11: other paths, headers
SECURITY_HEADERS = {"cache-control": "no-store", "x-content-type-options": "nosniff"}


def _assert_security_headers(response: httpx.Response) -> None:
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get_list(name) == [value], name


@pytest.mark.parametrize(
    "path", ["/nothing", "/", "/docs", "/redoc", "/openapi.json", "/bundles/", "/requests/"]
)
def test_unknown_path_is_404_not_found_with_security_headers(path: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).get(path, follow_redirects=False)

    assert (response.status_code, response.content) == (404, b'{"code":"NOT_FOUND"}')
    assert response.headers["content-type"] == "application/json"
    _assert_security_headers(response)
    assert relay.calls == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/bundles"),
        ("DELETE", "/bundles"),
        ("PUT", f"/requests/{INSTANCE}"),
        ("GET", f"/requests/{INSTANCE}"),
        ("POST", f"/responses/{CLIENT}"),
        ("OPTIONS", "/bundles"),
    ],
)
def test_unknown_method_is_405_method_not_allowed_with_security_headers(
    method: str, path: str
) -> None:
    relay = RecordingRelay()

    response = _client(relay).request(method, path, content=b"x", headers=OCTET)

    assert (response.status_code, response.content) == (405, b'{"code":"METHOD_NOT_ALLOWED"}')
    assert response.headers["content-type"] == "application/json"
    _assert_security_headers(response)
    assert relay.calls == []


def test_every_response_kind_carries_the_security_headers() -> None:
    relay = RecordingRelay()
    relay.pages[CLIENT] = ResponsePage((), None)
    origins = ("https://app.example",)
    limits = GatewayLimits(per_source_burst=7, cors_origins=origins)
    app = create_app(relay, limits=limits, clock=lambda: 0.0)
    client = TestClient(app, raise_server_exceptions=False)
    preflight = {"Origin": origins[0], "Access-Control-Request-Method": "POST"}

    responses = [
        client.get("/bundles"),
        client.post(f"/requests/{INSTANCE}", content=b"x", headers=OCTET),
        client.get(f"/responses/{CLIENT}"),
        client.post(f"/requests/{INSTANCE}", content=b"", headers=OCTET),
        client.options("/bundles", headers=preflight),
    ]
    relay.error = RuntimeError(SENTINEL)
    responses += [client.get("/bundles"), client.get("/bundles"), client.get("/bundles")]

    assert [r.status_code for r in responses] == [200, 202, 200, 400, 200, 500, 500, 429]
    for response in responses:
        _assert_security_headers(response)


# ---------------------------------------------------------------- logging (§6; SR-11)
def _gateway_lines(caplog: pytest.LogCaptureFixture) -> list[tuple[str, int, str, object]]:
    return [
        (r.name, r.levelno, r.getMessage(), getattr(r, "tc_fields", None))
        for r in caplog.records
        if r.name.startswith("teecustody")
    ]


@pytest.mark.parametrize(
    ("method", "path", "body", "error", "outcome"),
    [
        ("GET", "/bundles", b"", None, "GATEWAY_OK"),
        ("POST", f"/requests/{INSTANCE}", b"x", None, "GATEWAY_OK"),
        ("GET", f"/responses/{CLIENT}", b"", None, "GATEWAY_OK"),
        ("POST", f"/requests/{INSTANCE}", b"", None, "GATEWAY_INVALID_ARGUMENT"),
        ("GET", f"/responses/{CLIENT.upper()}", b"", None, "GATEWAY_INVALID_ARGUMENT"),
        (
            "POST",
            f"/requests/{INSTANCE}",
            b"x",
            QueueError(QueueErrorCode.NOT_FOUND),
            "GATEWAY_UNKNOWN_INSTANCE",
        ),
        ("GET", "/bundles", b"", QueueError(QueueErrorCode.UNAVAILABLE), "GATEWAY_UNAVAILABLE"),
        ("GET", "/bundles", b"", RuntimeError(SENTINEL), "GATEWAY_INTERNAL"),
        ("GET", "/nothing", b"", None, "GATEWAY_NOT_FOUND"),
        ("DELETE", "/bundles", b"", None, "GATEWAY_METHOD_NOT_ALLOWED"),
    ],
)
def test_each_request_logs_exactly_one_info_line_with_its_outcome_and_no_fields(
    method: str,
    path: str,
    body: bytes,
    error: Exception | None,
    outcome: str,
    all_logs: pytest.LogCaptureFixture,
) -> None:
    relay = RecordingRelay()
    relay.error = error
    client = TestClient(create_app(relay), raise_server_exceptions=False)

    client.request(method, path, content=body, headers=OCTET if body else None)

    assert _gateway_lines(all_logs) == [("teecustody.gateway", logging.INFO, outcome, {})]


def test_rate_limited_and_preflight_requests_are_logged_once_each(
    all_logs: pytest.LogCaptureFixture,
) -> None:
    origins = ("https://app.example",)
    limits = GatewayLimits(per_source_burst=1, per_source_rate=0.001, cors_origins=origins)
    client = TestClient(create_app(RecordingRelay(), limits=limits))
    preflight = {"Origin": origins[0], "Access-Control-Request-Method": "POST"}

    client.options("/bundles", headers=preflight)
    client.get("/bundles")

    assert [line[2] for line in _gateway_lines(all_logs)] == [
        "GATEWAY_OK",
        "GATEWAY_RATE_LIMITED",
    ]


def test_request_bodies_never_appear_in_logs_or_responses(
    all_logs: pytest.LogCaptureFixture,
) -> None:
    client = TestClient(create_app(RecordingRelay()), raise_server_exceptions=False)
    body = SENTINEL.encode()

    accepted = client.post(f"/requests/{INSTANCE}", content=body, headers=OCTET)
    oversize = client.post(f"/requests/{INSTANCE}", content=body * 10_000, headers=OCTET)
    wrong_type = client.post(f"/requests/{INSTANCE}", content=body, headers={"X": SENTINEL})

    assert [r.status_code for r in (accepted, oversize, wrong_type)] == [202, 400, 400]
    for text in (accepted.text, oversize.text, wrong_type.text, all_logs.text):
        assert SENTINEL not in text
        assert SENTINEL.encode().hex() not in text


# ---------------------------------------------------------------- edge cases
@pytest.mark.parametrize("query", ["after=a&after=b", "after=a&after=", "after=&after=a"])
def test_a_repeated_cursor_is_400_with_no_queue_call(query: str) -> None:
    relay = RecordingRelay()

    response = _client(relay).get(f"/responses/{CLIENT}?{query}")

    assert (response.status_code, response.content) == (400, INVALID)
    assert relay.calls == []


def test_route_id_pattern_equals_the_channel_hex32_pattern() -> None:
    from notes_gateway import app as gateway_app
    from teecustody.channel.codec import HEX32_PATTERN

    assert gateway_app._HEX32_PATTERN.pattern == HEX32_PATTERN.pattern


def test_importing_the_gateway_never_imports_cbor2_or_the_simulator() -> None:
    probe = (
        "import sys, notes_gateway; "
        "print(sorted(m for m in sys.modules if m.split('.')[0] in ('cbor2', 'teecustody_sim')))"
    )
    result = subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == "[]"


def test_a_client_disconnect_mid_body_releases_its_slots() -> None:
    relay = RecordingRelay()
    app = create_app(relay, limits=GatewayLimits(max_concurrency=1, per_source_max_in_flight=1))
    disconnect: list[Message] = [_chunk(b"ab", True), {"type": "http.disconnect"}]

    dropped = _drive(app, "POST", f"/requests/{INSTANCE}", _octet(5), disconnect)
    after = _drive(app, "GET", "/bundles", [], [])

    assert (dropped.status, after.status) == (400, 200)
