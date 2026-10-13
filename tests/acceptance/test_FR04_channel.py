"""FR-4 Secure request channel (INC-2): workload side, driven through public interfaces.

Client behaviour is implemented independently in `acc_channel.py` from INC-2-API sections 2 and 3.
Acceptance criteria (REQUIREMENTS FR-4):
  AC-1  valid pre-key -> HPKE Base session -> authenticated request/response
  AC-2  invalid authentication, invalid sequence, replay -> rejected without dispatch
plus the spec 13.3 protocol tests listed in INC-2-API section 14.

Owning tasks: T-07 (codec), T-08 (HPKE open), T-10 (replay), T-12 (audit emitter), T-22 (pre-keys),
T-23 (sessions, sealer), T-28 (ChannelServer). Expected failure on trunk: NotImplementedError('T-22')
at `PreKeyStore(...)`, the first stub every test reaches.
"""

import cbor2
import pytest

from acc_channel import (
    CLIENT_ID,
    CS,
    ChannelWorld,
    cannot_decrypt,
    cbor,
    flip_ct_bit,
    flip_hex_char,
    make_world,
    read_frame_result,
    read_open_result,
    retarget_open,
    seal_frame,
    uncbor,
)
from teecustody.channel import CloseReason

MAX_SEQ = 2**53 - 1


def outcome(result: object) -> str:
    return str(result.outcome)  # type: ignore[attr-defined]


def _open(world: ChannelWorld):  # type: ignore[no-untyped-def]
    sent, opened = world.established()
    assert opened.session_id is not None
    return sent, opened.session_id


# ------------------------------------------------------------------ AC-1
def test_FR04_valid_open_then_authenticated_request_and_response() -> None:
    # Given a workload with live pre-keys and a client holding the correct share
    world = make_world()
    entry = world.entries()[0]
    # When the client opens a session with a request sealed to that pre-key (HPKE Base)
    sent = world.open_session(entry=entry)
    result = world.server.process(sent.body)
    # Then the workload accepts, answers only on the AAD route, and the answer authenticates
    assert outcome(result) == "SESSION_OPENED"
    assert result.response is not None and result.response.client_id == CLIENT_ID
    opened = read_open_result(result.response.body, sent.t2c)
    assert opened.ok and opened.session_id is not None and len(opened.session_id) == 16
    assert opened.request_id == sent.request_id
    # When the client then sends an authenticated request in the session
    frame = seal_frame(sent.c2t, opened.session_id, 0, "test.echo", {"hello": "world", "n": 7})
    reply = world.server.process(frame)
    # Then the operation is dispatched once and the response authenticates under sk_t2c
    assert outcome(reply) == "FRAME_ACCEPTED"
    assert len(world.handler.calls) == 1
    assert world.handler.calls[0][1] == "test.echo"
    assert reply.response is not None and reply.response.client_id == CLIENT_ID
    answer = read_frame_result(reply.response.body, sent.t2c)
    assert answer.ok and answer.payload == {"hello": "world", "n": 7}
    assert answer.op == "test.echo" and answer.session_id == opened.session_id
    # And the response answers request seq 0 and uses t2c seq 1 (seq 0 was the open_result)
    assert answer.re == 0 and answer.seq == 1


def test_FR04_response_sequence_increases_by_one_per_answer() -> None:
    # Given an open session
    world = make_world()
    sent, sid = _open(world)
    # When three requests are answered
    seqs = []
    for i in range(3):
        reply = world.server.process(seal_frame(sent.c2t, sid, i, "test.echo", i))
        assert reply.response is not None
        seqs.append(read_frame_result(reply.response.body, sent.t2c).seq)
    # Then the t2c seq values are 1, 2, 3: each nonce is used once
    assert seqs == [1, 2, 3]


def test_FR04_close_ends_the_session_and_later_frames_get_no_answer() -> None:
    # Given an open session
    world = make_world()
    sent, sid = _open(world)
    # When the client sends the channel-handled "close" operation
    reply = world.server.process(seal_frame(sent.c2t, sid, 0, "close", None))
    # Then it is acknowledged, the session is gone, the opener is told, and the handler never saw it
    assert reply.response is not None
    answer = read_frame_result(reply.response.body, sent.t2c)
    assert answer.ok and answer.payload is None
    assert world.sessions.get(sid) is None
    assert (sid, CloseReason.CLIENT_CLOSE) in world.closes
    assert world.handler.calls == []
    # When a further frame arrives for the closed session
    late = world.server.process(seal_frame(sent.c2t, sid, 1, "test.echo", 1))
    # Then it is rejected silently and not dispatched
    assert outcome(late) == "SESSION_UNKNOWN" and late.response is None
    assert world.handler.calls == []


def test_FR04_gaps_in_sequence_numbers_are_accepted() -> None:
    # Given an open session where the queue may lose messages
    world = make_world()
    sent, sid = _open(world)
    assert world.server.process(seal_frame(sent.c2t, sid, 0, "test.echo", "a")).response
    # When seq jumps from 0 to 5
    reply = world.server.process(seal_frame(sent.c2t, sid, 5, "test.echo", "b"))
    # Then it is accepted (strictly greater than the last accepted)
    assert outcome(reply) == "FRAME_ACCEPTED" and reply.response is not None
    assert read_frame_result(reply.response.body, sent.t2c).re == 5


# ------------------------------------------------------------------ AC-2
def test_FR04_replayed_sequence_is_rejected_before_dispatch() -> None:
    # Given a session in which seq 0 was accepted
    world = make_world()
    sent, sid = _open(world)
    frame = seal_frame(sent.c2t, sid, 0, "test.echo", "once")
    assert outcome(world.server.process(frame)) == "FRAME_ACCEPTED"
    # When the identical frame is replayed
    again = world.server.process(frame)
    # Then it is rejected with no response and the operation ran exactly once
    assert outcome(again) == "FRAME_SEQ_REJECTED" and again.response is None
    assert len(world.handler.calls) == 1


@pytest.mark.parametrize("second", [0, 3, 4])
def test_FR04_non_increasing_sequence_is_rejected_before_dispatch(second: int) -> None:
    # Given a session whose last accepted c2t seq is 4
    world = make_world()
    sent, sid = _open(world)
    assert world.server.process(seal_frame(sent.c2t, sid, 4, "test.echo", "x")).response
    calls = len(world.handler.calls)
    # When a frame with seq equal to or below it arrives (correctly encrypted)
    result = world.server.process(seal_frame(sent.c2t, sid, second, "test.echo", "y"))
    # Then it is rejected without dispatch
    assert outcome(result) == "FRAME_SEQ_REJECTED" and result.response is None
    assert len(world.handler.calls) == calls


def test_FR04_sequence_above_max_is_a_schema_failure() -> None:
    # Given an open session
    world = make_world()
    sent, sid = _open(world)
    # When a frame declares seq = 2^53 (one above MAX_SEQ, D2-15)
    result = world.server.process(seal_frame(sent.c2t, sid, MAX_SEQ + 1, "test.echo", "x"))
    # Then it is rejected as an invalid request and never dispatched
    assert outcome(result) == "REQUEST_INVALID" and result.response is None
    assert world.handler.calls == []


def _tamper_ct(body: bytes) -> bytes:
    return flip_ct_bit(body)


def _tamper_op(body: bytes) -> bytes:
    env = uncbor(body)
    aad = uncbor(env["aad"])
    aad["op"] = "test.other"
    return cbor({"kind": "frame", "aad": cbor(aad), "ct": env["ct"]})


def _tamper_seq(body: bytes) -> bytes:
    env = uncbor(body)
    aad = uncbor(env["aad"])
    aad["seq"] = aad["seq"] + 1
    return cbor({"kind": "frame", "aad": cbor(aad), "ct": env["ct"]})


@pytest.mark.parametrize("tamper", [_tamper_ct, _tamper_op, _tamper_seq])
def test_FR04_frame_with_invalid_authentication_is_rejected_and_state_unchanged(
    tamper,  # type: ignore[no-untyped-def]
) -> None:
    # Given an open session
    world = make_world()
    sent, sid = _open(world)
    good = seal_frame(sent.c2t, sid, 1, "test.echo", "x")
    # When the frame is altered in ciphertext, AAD op, or AAD seq (any one change to the AAD)
    bad = world.server.process(tamper(good))
    # Then authentication fails: no response, no dispatch
    assert outcome(bad) == "FRAME_AUTH_FAILED" and bad.response is None
    assert world.handler.calls == []
    # And the failure did not consume the sequence number: the genuine frame still works
    ok = world.server.process(good)
    assert outcome(ok) == "FRAME_ACCEPTED" and len(world.handler.calls) == 1


def test_FR04_frame_under_a_wrong_key_is_rejected_without_dispatch() -> None:
    # Given an open session and a different session key
    world = make_world()
    _, sid = _open(world)
    # When a frame is sealed with a key the workload does not hold
    result = world.server.process(seal_frame(bytes(32), sid, 0, "test.echo", "x"))
    # Then it is rejected
    assert outcome(result) == "FRAME_AUTH_FAILED" and result.response is None
    assert world.handler.calls == []


def test_FR04_frame_for_an_unknown_session_is_rejected_without_dispatch() -> None:
    # Given a workload with no session
    world = make_world()
    # When a frame names a session id that was never issued
    result = world.server.process(seal_frame(bytes(32), bytes(16), 0, "test.echo", "x"))
    # Then it is dropped without a response
    assert outcome(result) == "SESSION_UNKNOWN" and result.response is None
    assert world.handler.calls == []


def test_FR04_open_with_wrong_client_share_is_refused_with_no_session() -> None:
    # Given a workload that knows client CLIENT_ID's share
    world = make_world()
    # When a client claiming that id presents a different share
    sent = world.open_session(cs=bytes(32))
    result = world.server.process(sent.body)
    # Then the client (who holds the keys) gets an authenticated refusal with no session id
    assert outcome(result) == "OPEN_REJECTED"
    assert result.response is not None and result.response.client_id == CLIENT_ID
    opened = read_open_result(result.response.body, sent.t2c)
    assert not opened.ok and opened.session_id is None
    assert opened.error == "AUTHENTICATION_FAILED"
    # And no session exists
    assert world.sessions.get(bytes(16)) is None
    assert len(world.opener.requests) == 1  # type: ignore[attr-defined]


def test_FR04_open_replayed_verbatim_is_rejected_before_the_opener() -> None:
    # Given a successful open
    world = make_world()
    sent = world.open_session()
    assert outcome(world.server.process(sent.body)) == "SESSION_OPENED"
    # When the identical bytes arrive again
    again = world.server.process(sent.body)
    # Then they are rejected silently (the pre-key is spent; the request id is recorded)
    assert outcome(again) in {"PREKEY_UNKNOWN", "REQUEST_REPLAYED"}
    assert again.response is None
    assert len(world.opener.requests) == 1  # type: ignore[attr-defined]


def test_FR04_prekey_reuse_with_a_fresh_request_is_rejected() -> None:
    # Given a pre-key that has been consumed by one open
    world = make_world()
    entry = world.entries()[0]
    assert outcome(world.server.process(world.open_session(entry=entry).body)) == "SESSION_OPENED"
    # When a second, entirely new request is sealed to the same pre-key
    second = world.server.process(world.open_session(entry=entry, route="c3" * 16).body)
    # Then it is rejected as an unknown pre-key (single use)
    assert outcome(second) == "PREKEY_UNKNOWN" and second.response is None
    with pytest.raises(KeyError):
        world.prekeys.take(entry.id)


def test_FR04_expired_prekey_is_rejected() -> None:
    # Given a pre-key and a clock beyond its not_after
    world = make_world()
    entry = world.entries()[0]
    world.clock.now = entry.not_after + 1
    # When a client uses it
    result = world.server.process(world.open_session(entry=entry).body)
    # Then it is unknown
    assert outcome(result) == "PREKEY_UNKNOWN" and result.response is None


@pytest.mark.parametrize("delta", [-301, 301])
def test_FR04_stale_or_future_timestamp_is_rejected(delta: int) -> None:
    # Given the default 300 s request skew
    world = make_world()
    # When the open is timestamped outside the skew window
    sent = world.open_session(timestamp=world.now_s() + delta)
    result = world.server.process(sent.body)
    # Then it is rejected without response or opener call
    assert outcome(result) == "REQUEST_STALE" and result.response is None
    assert world.opener.requests == []  # type: ignore[attr-defined]


@pytest.mark.parametrize("delta", [-300, 300])
def test_FR04_timestamp_exactly_at_the_skew_boundary_is_accepted(delta: int) -> None:
    # Given the default 300 s request skew
    world = make_world()
    # When the open is timestamped exactly skew seconds away
    sent = world.open_session(timestamp=world.now_s() + delta)
    # Then it is accepted
    assert outcome(world.server.process(sent.body)) == "SESSION_OPENED"


def test_FR04_open_moved_to_another_instance_is_rejected() -> None:
    # Given two workload instances with different identities
    a, b = make_world(), make_world()
    sent = a.open_session()
    # When A's open envelope is delivered to B
    moved = b.server.process(sent.body)
    # Then B rejects it as addressed elsewhere
    assert outcome(moved) == "REQUEST_WRONG_INSTANCE" and moved.response is None
    # And rewriting instance_id and prekey_id to B's values still fails HPKE Open
    rewritten = retarget_open(sent, instance_id=b.instance_id, prekey_id=b.entries()[0].id)
    result = b.server.process(rewritten)
    assert outcome(result) == "OPEN_FAILED" and result.response is None
    assert b.opener.requests == []  # type: ignore[attr-defined]


@pytest.mark.parametrize("field_name", ["client_id", "request_id", "timestamp", "prekey_id"])
def test_FR04_any_one_change_to_the_open_aad_fails_hpke_open(field_name: str) -> None:
    # Given a well-formed open and a second live pre-key
    world = make_world()
    sent = world.open_session()
    other_id = world.entries()[1].id
    changed = {
        "client_id": flip_hex_char(sent.aad["client_id"]),
        "request_id": bytes([sent.request_id[0] ^ 1]) + sent.request_id[1:],
        "timestamp": sent.aad["timestamp"] + 1,
        "prekey_id": other_id,
    }[field_name]
    # When one AAD field is changed and everything else is left byte-identical
    result = world.server.process(retarget_open(sent, **{field_name: changed}))
    # Then the AAD no longer authenticates: nothing is opened, nothing is dispatched
    assert outcome(result) == "OPEN_FAILED" and result.response is None
    assert world.opener.requests == []  # type: ignore[attr-defined]


def test_FR04_open_sealed_with_the_wrong_hpke_info_fails() -> None:
    # Given a client that bound its seal to pre-key id+1 in the HPKE info (spec 5.3 step 9)
    world = make_world()
    entry = world.entries()[0]
    sent = world.open_session(entry=entry, info_prekey_id=entry.id + 1)
    # When the workload opens it
    result = world.server.process(sent.body)
    # Then HPKE Open fails and the pre-key is spent
    assert outcome(result) == "OPEN_FAILED" and result.response is None


def test_FR04_all_zero_encapsulated_key_is_rejected_without_error() -> None:
    # Given an open envelope whose `enc` is the all-zero (low-order) X25519 point
    world = make_world()
    sent = world.open_session()
    env = uncbor(sent.body)
    env["enc"] = bytes(32)
    # When processed
    result = world.server.process(cbor(env))
    # Then it fails closed (no exception, no response)
    assert outcome(result) == "OPEN_FAILED" and result.response is None


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\xff\xff\xff",
        cbor(None),
        cbor([1, 2]),
        cbor({"kind": "open"}),
        cbor({"kind": "bogus", "aad": b"", "ct": b""}),
        cbor({"kind": "frame", "aad": b"x", "ct": bytes(32)}),
        b"\x00" * 65537,
    ],
    ids=["empty", "garbage", "null", "array", "missing-keys", "bad-kind", "bad-aad", "oversize"],
)
def test_FR04_malformed_requests_are_dropped_without_raising(body: bytes) -> None:
    # Given a running channel
    world = make_world()
    # When arbitrary malformed bytes arrive
    result = world.server.process(body)
    # Then they are counted as invalid, nothing answers and nothing runs
    assert outcome(result) == "REQUEST_INVALID" and result.response is None
    assert world.handler.calls == [] and world.opener.requests == []  # type: ignore[attr-defined]


def test_FR04_noncanonical_cbor_is_rejected() -> None:
    # Given a structurally valid open envelope re-encoded with non-canonical key order
    world = make_world()
    sent = world.open_session()
    env = uncbor(sent.body)
    reordered = cbor2.dumps({"kind": "open", "ct": env["ct"], "enc": env["enc"], "aad": env["aad"]})
    assert reordered != sent.body
    # When processed
    result = world.server.process(reordered)
    # Then it is rejected as invalid
    assert outcome(result) == "REQUEST_INVALID" and result.response is None


def test_FR04_times_beyond_two_to_the_53_are_a_schema_failure() -> None:
    # Given an open whose AAD timestamp is 2^53 (R-1)
    world = make_world()
    sent = world.open_session()
    # When processed
    result = world.server.process(retarget_open(sent, timestamp=2**53))
    # Then it is an invalid request (not a stale one)
    assert outcome(result) == "REQUEST_INVALID" and result.response is None


def test_FR04_forward_secrecy_captured_transcript_cannot_be_replayed_after_close() -> None:
    # Given a full session (open, request, close) captured by a network observer
    world = make_world()
    sent, sid = _open(world)
    frame = seal_frame(sent.c2t, sid, 0, "test.echo", "secret")
    assert world.server.process(frame).response is not None
    close = seal_frame(sent.c2t, sid, 1, "close", None)
    assert world.server.process(close).response is not None
    # Then the pre-key private key is gone from the store
    with pytest.raises(KeyError):
        world.prekeys.take(sent.prekey_id)
    # When the transcript is replayed into a fresh server holding the same identity key
    fresh = make_world(identity=world.identity, instance_id=world.instance_id)
    for captured in (sent.body, frame, close):
        result = fresh.server.process(captured)
        # Then nothing opens, nothing answers, nothing is dispatched
        assert outcome(result) in {"PREKEY_UNKNOWN", "OPEN_FAILED", "SESSION_UNKNOWN"}
        assert result.response is None
    assert fresh.handler.calls == [] and fresh.opener.requests == []  # type: ignore[attr-defined]
    assert fresh.sessions.get(sid) is None


def test_FR04_a_response_authenticates_only_under_its_own_sessions_key() -> None:
    # Given two clients with sessions on the same workload
    world = make_world(shares={CLIENT_ID: CS, "c4" * 16: CS})
    first, opened_first = world.established(route=CLIENT_ID)
    second, _ = world.established(route="c4" * 16)
    assert opened_first.session_id is not None
    # When the first client's answer is examined
    reply = world.server.process(seal_frame(first.c2t, opened_first.session_id, 0, "test.echo", 1))
    # Then only the first client's key opens it; the second client's key does not
    assert reply.response is not None and reply.response.client_id == CLIENT_ID
    assert read_frame_result(reply.response.body, first.t2c).ok
    assert cannot_decrypt(reply.response.body, second.t2c)


def test_FR04_published_prekeys_are_signed_by_the_identity_key() -> None:
    # Given a workload's published pre-key entries
    world = make_world()
    from acc_channel import prekey_signature_valid

    # Then every entry verifies under IK_pub over the spec-5.1 message, ids strictly ascending
    entries = world.entries()
    assert len(entries) >= 1
    assert [e.id for e in entries] == sorted({e.id for e in entries})
    ik_pub = world.identity.public_bytes()
    assert all(prekey_signature_valid(ik_pub, world.instance_id, e) for e in entries)
    assert all(e.not_after > world.now_s() for e in entries)
