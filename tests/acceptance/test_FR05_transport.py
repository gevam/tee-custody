"""FR-5 queue-based transport and SR-1 / SR-3 / SR-4 gateway behaviour (INC-2).

Acceptance criterion (REQUIREMENTS FR-5): given the reference gateway and in-memory queue, when a
browser client posts a request and polls for its response, then both are relayed to the correct
workload instance and client. The workload exposes no inbound endpoint (NFR-2: test_SR04_limits.py).

Owning tasks: T-14 (gateway), T-24 (in-memory queue), T-29 (run loop), T-22/T-28/T-23 (channel).
Expected failure on trunk: NotImplementedError('T-14') at `create_app`, 'T-24' at `InMemoryQueue`,
'T-29' at `RunLoop`. Gateway tests use a spy RelayQueue so they depend on T-14 alone.
"""

import hashlib
from typing import Any

import pytest
from notes_gateway import GatewayLimits, create_app
from starlette.testclient import TestClient

from acc_channel import (
    CLIENT_ID,
    CS,
    OTHER_CLIENT_ID,
    b64u,
    cannot_decrypt,
    prekey_signature_valid,
    read_frame_result,
    read_open_result,
    seal_frame,
    unb64u,
    uncbor,
)
from acc_runloop import IID, OCTET, SpyRelay, make_run_world
from acc_support import START_TIME, FakeClock, RunningSim, decode_jws
from teecustody.queue import PublishedBundle, PublishedResponse, QueueError, QueueErrorCode
from teecustody_sim.backends import InMemoryQueue

HEX = "cd" * 16


def _client(relay: SpyRelay, limits: GatewayLimits | None = None, **kw: Any) -> TestClient:
    app = create_app(relay, limits=limits or GatewayLimits(), **kw)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------- reference gateway contract
def test_FR05_gateway_lists_bundles_without_any_credentials() -> None:
    # Given a gateway over a queue holding one bundle
    relay = SpyRelay()
    # When an anonymous client lists bundles
    resp = _client(relay).get("/bundles")
    # Then it gets the bundle, base64url without padding, and hardening headers
    assert resp.status_code == 200
    assert resp.json() == {"bundles": [{"instance_id": IID, "bundle": b64u(b"bundle-bytes")}]}
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_FR05_gateway_never_returns_more_bundles_than_configured() -> None:
    # Given 5 bundles and max_bundles = 2
    relay = SpyRelay()
    relay.bundles = [PublishedBundle(f"{i:032x}", b"b") for i in range(5)]
    # When listing
    resp = _client(relay, GatewayLimits(max_bundles=2)).get("/bundles")
    # Then at most 2 are returned and the queue was asked for no more than 2
    assert len(resp.json()["bundles"]) <= 2
    assert all(c[1] <= 2 for c in relay.calls if c[0] == "list")


def test_FR05_gateway_relays_a_request_to_the_named_instance_with_a_relay_id() -> None:
    # Given a gateway with a deterministic id source
    relay = SpyRelay()
    client = _client(relay, rng=lambda n: bytes([0x5A]) * n)
    # When a browser posts an envelope for an instance
    resp = client.post(f"/requests/{IID}", content=b"\x01\x02ciphertext", headers=OCTET)
    # Then 202 with the gateway-minted relay request id, and the exact bytes reach the queue
    assert resp.status_code == 202 and resp.json() == {"request_id": "5a" * 16}
    assert relay.requests == [(IID, "5a" * 16, b"\x01\x02ciphertext")]
    assert b"ciphertext" not in resp.content  # the body is never echoed


def test_FR05_gateway_answers_404_for_an_unknown_instance_with_the_stable_body() -> None:
    # Given a gateway whose queue knows only IID
    resp = _client(SpyRelay()).post(f"/requests/{HEX}", content=b"x", headers=OCTET)
    # Then 404 with exactly the stable error body
    assert resp.status_code == 404 and resp.json() == {"code": "UNKNOWN_INSTANCE"}


@pytest.mark.parametrize(
    "bad",
    [IID.upper(), IID[:-1], IID + "a", "g" * 32],
    ids=["uppercase", "31-chars", "33-chars", "non-hex"],
)
def test_FR05_malformed_route_ids_are_rejected_before_any_queue_call(bad: str) -> None:
    # Given a gateway and a spy queue
    relay = SpyRelay()
    client = _client(relay)
    # When route ids are malformed
    post = client.post(f"/requests/{bad}", content=b"x", headers=OCTET)
    get = client.get(f"/responses/{bad}")
    # Then both are 400 INVALID_ARGUMENT and the queue was never called
    for resp in (post, get):
        assert resp.status_code == 400 and resp.json() == {"code": "INVALID_ARGUMENT"}
    assert relay.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/bundles%0A",
        "/bundles%00",
        f"/requests/{IID}%0A",
        f"/responses/{HEX}%0D",
        "/bundles%7F",
    ],
)
def test_FR05_control_characters_in_the_path_are_404_before_routing(path: str) -> None:
    # Given a gateway and a spy queue (T-14 A1: control characters are refused before routing)
    relay = SpyRelay()
    client = _client(relay)
    # When a decoded path carries a control character
    resp = (
        client.post(path, content=b"x", headers=OCTET) if "/requests/" in path else client.get(path)
    )
    # Then 404 NOT_FOUND and no queue call
    assert resp.status_code == 404 and resp.json() == {"code": "NOT_FOUND"}
    assert relay.calls == []


@pytest.mark.parametrize(
    ("kwargs", "label"),
    [
        ({"content": b"", "headers": OCTET}, "empty-body"),
        ({"content": b"x" * 65537, "headers": OCTET}, "oversize"),
        ({"content": b"x", "headers": {"Content-Type": "application/json"}}, "wrong-type"),
        ({"content": b"x"}, "no-type"),
    ],
)
def test_FR05_invalid_request_bodies_are_rejected_before_any_queue_call(
    kwargs: dict[str, Any], label: str
) -> None:
    # Given a gateway with the default 65,536-byte request limit
    relay = SpyRelay()
    # When the body is empty, oversize, or has the wrong content type
    resp = _client(relay).post(f"/requests/{IID}", **kwargs)
    # Then 400 INVALID_ARGUMENT with no queue call
    assert resp.status_code == 400 and resp.json() == {"code": "INVALID_ARGUMENT"}, label
    assert relay.calls == []


def test_FR05_gateway_returns_responses_for_a_client_route_with_cursor() -> None:
    # Given two responses waiting on a client route
    relay = SpyRelay()
    relay.responses[HEX] = [
        PublishedResponse("aa" * 16, b"first"),
        PublishedResponse("bb" * 16, b"second"),
    ]
    client = _client(relay)
    # When polling with and without a cursor
    resp = client.get(f"/responses/{HEX}", params={"after": "7"})
    # Then both are returned in order as base64url and the cursor reaches the queue unmodified
    assert resp.status_code == 200
    assert resp.json() == {
        "responses": [
            {"request_id": "aa" * 16, "body": b64u(b"first")},
            {"request_id": "bb" * 16, "body": b64u(b"second")},
        ],
        "next": None,
    }
    assert ("pull", HEX, "7", 32) in [c[:4] for c in relay.calls if c[0] == "pull"]


def test_FR05_unknown_client_route_returns_an_empty_page_not_an_error() -> None:
    # Given a route nobody has ever used (route probing must reveal nothing, D2-13)
    resp = _client(SpyRelay()).get(f"/responses/{OTHER_CLIENT_ID}")
    # Then 200 with an empty page
    assert resp.status_code == 200 and resp.json()["responses"] == []


def test_FR05_page_size_never_exceeds_max_page() -> None:
    # Given 10 waiting responses and max_page = 3
    relay = SpyRelay()
    relay.responses[HEX] = [PublishedResponse(f"{i:032x}", b"b") for i in range(10)]
    resp = _client(relay, GatewayLimits(max_page=3)).get(f"/responses/{HEX}")
    # Then at most 3 are returned
    assert len(resp.json()["responses"]) <= 3
    assert all(c[3] <= 3 for c in relay.calls if c[0] == "pull")


@pytest.mark.parametrize("cursor", ["bad cursor!", "a" * 129, "%0A", ""])
def test_FR05_invalid_cursors_are_rejected_before_any_queue_call(cursor: str) -> None:
    relay = SpyRelay()
    resp = _client(relay).get(f"/responses/{HEX}", params={"after": cursor})
    assert resp.status_code == 400 and resp.json() == {"code": "INVALID_ARGUMENT"}
    assert relay.calls == []


def test_FR05_other_paths_and_methods_get_stable_error_bodies() -> None:
    client = _client(SpyRelay())
    assert client.get("/nothing").json() == {"code": "NOT_FOUND"}
    not_allowed = client.post("/bundles", content=b"x", headers=OCTET)
    assert not_allowed.status_code == 405 and not_allowed.json() == {"code": "METHOD_NOT_ALLOWED"}
    assert client.get("/nothing").headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (QueueError(QueueErrorCode.UNAVAILABLE), 503, "UNAVAILABLE"),
        (QueueError(QueueErrorCode.INTERNAL), 500, "INTERNAL"),
        (RuntimeError("SENTINEL-PROVIDER-TEXT-91c"), 500, "INTERNAL"),
    ],
)
def test_FR05_backend_failures_map_to_stable_codes_without_leaking_causes(
    error: Exception, status: int, code: str, caplog: pytest.LogCaptureFixture
) -> None:
    # Given a queue that fails with provider text in the exception
    relay = SpyRelay()
    relay.raise_on_list = error
    # When a client lists bundles
    resp = _client(relay).get("/bundles")
    # Then only the stable code crosses the boundary; the cause is in neither body nor logs
    assert resp.status_code == status and resp.json() == {"code": code}
    assert "SENTINEL-PROVIDER-TEXT-91c" not in resp.text + caplog.text


# ---------------------------------------------------------------- SR-4 gateway budgets
def test_SR04_per_source_budget_answers_429_before_the_queue_is_called() -> None:
    # Given a per-source burst of 2 and a frozen clock (no refill)
    relay, clock = SpyRelay(), FakeClock(1000.0)
    client = _client(
        relay,
        GatewayLimits(per_source_burst=2, per_source_rate=0.001),
        clock=clock,
    )
    # When one source sends three requests
    codes = [client.get("/bundles").status_code for _ in range(3)]
    # Then the third is 429 RATE_LIMITED with an integer Retry-After, and the queue saw two calls
    assert codes == [200, 200, 429]
    limited = client.get("/bundles")
    assert limited.json() == {"code": "RATE_LIMITED"}
    assert limited.headers["retry-after"].isdigit()
    assert len(relay.calls) == 2
    # And after time passes the source is served again
    clock.now += 5000
    assert client.get("/bundles").status_code == 200


def test_SR04_global_budget_answers_429_before_the_queue_is_called() -> None:
    # Given a global burst of 1 and a frozen clock
    relay, clock = SpyRelay(), FakeClock(1000.0)
    client = _client(relay, GatewayLimits(global_burst=1, global_rate=0.001), clock=clock)
    # When two requests arrive
    first, second = client.get("/bundles"), client.get("/bundles")
    # Then the second is rejected with no queue call
    assert (first.status_code, second.status_code) == (200, 429)
    assert second.json() == {"code": "RATE_LIMITED"} and len(relay.calls) == 1


# ---------------------------------------------------------------- CORS (security note c)
def test_FR05_default_gateway_sends_no_cors_headers_at_all() -> None:
    resp = _client(SpyRelay()).get("/bundles", headers={"Origin": "https://evil.example"})
    assert not [h for h in resp.headers if h.lower().startswith("access-control-")]


def test_FR05_only_exact_allow_listed_origins_are_echoed_and_credentials_never() -> None:
    # Given an allow-list of one origin
    client = _client(SpyRelay(), GatewayLimits(cors_origins=("https://app.example",)))
    # When the allowed and a different origin request
    ok = client.get("/bundles", headers={"Origin": "https://app.example"})
    other = client.get("/bundles", headers={"Origin": "https://app.example.evil"})
    # Then only the exact match is echoed, with Vary: Origin; credentials are never allowed
    assert ok.headers["access-control-allow-origin"] == "https://app.example"
    assert "origin" in ok.headers["vary"].lower()
    assert "access-control-allow-origin" not in other.headers
    assert "access-control-allow-credentials" not in ok.headers
    # And the preflight allows only GET/POST and Content-Type
    pre = client.options(
        "/requests/" + IID,
        headers={
            "Origin": "https://app.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert pre.status_code == 200
    assert "access-control-allow-credentials" not in pre.headers
    methods = {m.strip() for m in pre.headers["access-control-allow-methods"].split(",")}
    assert methods <= {"GET", "POST"}


@pytest.mark.parametrize(
    "origin", ["*", "null", "http://evil.example", "https://app.example/", "https://app.example/x"]
)
def test_FR05_invalid_cors_origins_are_refused_at_startup(origin: str) -> None:
    with pytest.raises(ValueError, match="INVALID_CORS_ORIGIN"):
        create_app(SpyRelay(), limits=GatewayLimits(cors_origins=(origin,)))


@pytest.mark.parametrize(
    "limits",
    [
        GatewayLimits(max_request_bytes=0),
        GatewayLimits(max_page=-1),
        GatewayLimits(per_source_rate=float("nan")),
        GatewayLimits(global_rate=0.0),
        GatewayLimits(max_concurrency=True),
    ],
    ids=["zero-bytes", "negative-page", "nan-rate", "zero-rate", "bool-int"],
)
def test_FR05_invalid_limits_are_refused_at_startup(limits: GatewayLimits) -> None:
    with pytest.raises(ValueError, match="INVALID_LIMITS"):
        create_app(SpyRelay(), limits=limits)


# ---------------------------------------------------------------- in-memory queue routing
def test_FR05_queue_routes_requests_to_the_named_instance_only() -> None:
    # Given two instances with live bundles
    clock = FakeClock(START_TIME)
    queue = InMemoryQueue(clock=clock)
    a, b = "aa" * 16, "bb" * 16
    exp = int(clock()) + 3600
    queue.publish_bundle(a, b"bundle-a", exp)
    queue.publish_bundle(b, b"bundle-b", exp)
    # When a request is published for A
    queue.publish_request(a, "01" * 16, b"for-a")
    # Then only A pulls it (and the message carries the relay request id)
    assert [m.body for m in queue.pull_requests(b, 10, 0.01)] == []
    pulled = queue.pull_requests(a, 10, 0.01)
    assert [(m.body, m.request_id) for m in pulled] == [(b"for-a", "01" * 16)]
    # And publishing for an instance without a live bundle is NOT_FOUND
    with pytest.raises(QueueError) as exc:
        queue.publish_request("cc" * 16, "02" * 16, b"x")
    assert exc.value.code is QueueErrorCode.NOT_FOUND


def test_FR05_queue_redelivers_unacked_requests_and_drops_acked_ones() -> None:
    # Given a pulled but un-acked request and a 30 s ack deadline
    clock = FakeClock(START_TIME)
    queue = InMemoryQueue(clock=clock, ack_deadline_s=30.0)
    queue.publish_bundle(IID, b"b", int(clock()) + 3600)
    queue.publish_request(IID, "01" * 16, b"once")
    first = queue.pull_requests(IID, 10, 0.01)
    assert len(first) == 1
    # Then it is invisible until the deadline, and visible again after
    assert queue.pull_requests(IID, 10, 0.01) == []
    clock.now += 31
    again = queue.pull_requests(IID, 10, 0.01)
    assert [m.body for m in again] == [b"once"]
    # When acked it is gone for good
    queue.ack(again[0].message_id)
    clock.now += 31
    assert queue.pull_requests(IID, 10, 0.01) == []


def test_FR05_queue_delivers_responses_only_on_their_client_route_in_order() -> None:
    # Given responses for two clients
    queue = InMemoryQueue()
    for i in range(3):
        queue.publish_response(CLIENT_ID, f"{i:032x}", f"to-a-{i}".encode())
    queue.publish_response(OTHER_CLIENT_ID, "ff" * 16, b"to-b")
    # When client A pages with a cursor
    page = queue.pull_responses(CLIENT_ID, None, 2)
    rest = queue.pull_responses(CLIENT_ID, page.next, 2)
    # Then it sees only its own, in order, with no overlap
    assert [r.body for r in page.responses] == [b"to-a-0", b"to-a-1"]
    assert [r.body for r in rest.responses] == [b"to-a-2"]
    assert [r.body for r in queue.pull_responses(OTHER_CLIENT_ID, None, 10).responses] == [b"to-b"]
    with pytest.raises(QueueError) as exc:
        queue.pull_responses(CLIENT_ID, "not-a-cursor", 2)
    assert exc.value.code is QueueErrorCode.INVALID_ARGUMENT


# ---------------------------------------------------------------- end to end through the gateway
def _poll(client: TestClient, route: str, relay_id: str) -> bytes:
    resp = client.get(f"/responses/{route}")
    assert resp.status_code == 200
    for item in resp.json()["responses"]:
        if item["request_id"] == relay_id:
            return unb64u(item["body"])
    raise AssertionError("no response for the relay request id")


def test_FR05_request_and_response_are_relayed_to_the_right_workload_and_client(
    running_sim: RunningSim,
) -> None:
    # Given a workload (run loop over the in-memory queue) and the reference gateway
    world = make_run_world(running_sim, shares={CLIENT_ID: CS, OTHER_CLIENT_ID: CS})
    http = TestClient(create_app(world.queue))
    # When a browser lists bundles
    listing = http.get("/bundles").json()["bundles"]
    # Then it finds this instance's bundle, which is bound to the workload's identity key
    assert [b["instance_id"] for b in listing] == [world.loop.instance_id]
    bundle = uncbor(unb64u(listing[0]["bundle"]))
    ik_pub = bundle["IK_pub"]
    _header, claims = decode_jws(bundle["token"])
    nonce_claim = claims["eat_nonce"]
    assert (nonce_claim if isinstance(nonce_claim, str) else nonce_claim[0]) == hashlib.sha256(
        ik_pub
    ).hexdigest()
    ids = [e["id"] for e in bundle["prekeys"]]
    assert ids == sorted(set(ids)) and ids
    assert all(prekey_signature_valid(ik_pub, bundle["instance_id"], e) for e in bundle["prekeys"])
    # When two clients each open a session through the gateway
    sessions = {}
    for route in (CLIENT_ID, OTHER_CLIENT_ID):
        sent = world.open_session(route=route)
        post = http.post(f"/requests/{world.loop.instance_id}", content=sent.body, headers=OCTET)
        assert post.status_code == 202
        world.tick()
        body = _poll(http, route, post.json()["request_id"])
        opened = read_open_result(body, sent.t2c)
        assert opened.ok and opened.session_id is not None
        sessions[route] = (sent, opened.session_id)
    # And each sends a request and polls its own route
    for route, (sent, sid) in sessions.items():
        frame = seal_frame(sent.c2t, sid, 0, "test.echo", {"for": route})
        post = http.post(f"/requests/{world.loop.instance_id}", content=frame, headers=OCTET)
        world.tick()
        answer = read_frame_result(_poll(http, route, post.json()["request_id"]), sent.t2c)
        # Then each gets its own answer, and the other client's key cannot open it
        assert answer.ok and answer.payload == {"for": route}
        other_sent = next(s for r, (s, _) in sessions.items() if r != route)
        assert cannot_decrypt(_poll(http, route, post.json()["request_id"]), other_sent.t2c)
    # And a route nobody used yields nothing
    assert http.get(f"/responses/{'ee' * 16}").json()["responses"] == []


def test_SR01_possessing_a_route_id_does_not_establish_identity(running_sim: RunningSim) -> None:
    # Given a victim with a live session and an attacker who knows the victim's client id
    world = make_run_world(running_sim)
    http = TestClient(create_app(world.queue))
    victim = world.open_session()
    post = http.post(f"/requests/{world.loop.instance_id}", content=victim.body, headers=OCTET)
    world.tick()
    victim_open = read_open_result(_poll(http, CLIENT_ID, post.json()["request_id"]), victim.t2c)
    assert victim_open.session_id is not None
    # When the attacker (no credentials) opens claiming the victim's id with a wrong share
    attack = world.open_session(cs=bytes(32))
    http.post(f"/requests/{world.loop.instance_id}", content=attack.body, headers=OCTET)
    world.tick()
    # Then the attempt is refused and the operation never ran
    refused = [
        read_open_result(body, attack.t2c)
        for _rid, body in world.responses(CLIENT_ID)
        if not cannot_decrypt(body, attack.t2c)
    ]
    assert [r.error for r in refused] == ["AUTHENTICATION_FAILED"]
    assert world.handler.calls == []
    # And a frame for the victim's session, sealed without the victim's key, is dropped silently
    before = len(world.responses(CLIENT_ID))
    forged = seal_frame(bytes(32), victim_open.session_id, 0, "test.echo", "x")
    http.post(f"/requests/{world.loop.instance_id}", content=forged, headers=OCTET)
    world.tick()
    assert len(world.responses(CLIENT_ID)) == before
    assert world.handler.calls == []


def test_FR05_shutdown_withdraws_the_bundle_and_closes_sessions(running_sim: RunningSim) -> None:
    # Given a workload with an open session
    world = make_run_world(running_sim)
    sent = world.open_session()
    world.post(sent.body)
    world.tick()
    assert world.queue.list_bundles(16)
    # When the workload shuts down
    world.loop.shutdown()
    # Then its bundle is withdrawn and the session is closed with SHUTDOWN
    assert world.queue.list_bundles(16) == []
    assert [str(r) for _sid, r in world.opener.closed_calls] == ["SHUTDOWN"]
