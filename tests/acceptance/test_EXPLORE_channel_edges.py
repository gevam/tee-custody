"""QA exploratory (INC-2 phase 2): channel edge inputs against the workload ChannelServer.

Properties: process() never raises for message content; an invalid frame/open never dispatches
and never produces a response; the session stays usable after a rejected frame. Synthetic values only.
Client behaviour comes from the independent `acc_channel.py`.
"""

import cbor2
import pytest

from acc_channel import (
    cbor,
    make_world,
    read_frame_result,
    retarget_open,
    seal_frame,
    uncbor,
)

MAX_SEQ = 2**53 - 1


def _session():  # type: ignore[no-untyped-def]
    world = make_world()
    sent, opened = world.established()
    assert opened.session_id is not None
    return world, sent, opened.session_id


def _alive(world, sent, sid, seq):  # type: ignore[no-untyped-def]
    r = world.server.process(seal_frame(sent.c2t, sid, seq, "test.echo", "alive"))
    assert str(r.outcome) == "FRAME_ACCEPTED" and r.response is not None
    return read_frame_result(r.response.body, sent.t2c)


def test_seq_zero_is_the_first_accepted_value_and_max_seq_is_accepted() -> None:
    world, sent, sid = _session()
    assert _alive(world, sent, sid, 0).ok
    assert _alive(world, sent, sid, MAX_SEQ).ok
    # nothing can follow MAX_SEQ
    r = world.server.process(seal_frame(sent.c2t, sid, MAX_SEQ, "test.echo", "x"))
    assert r.response is None
    assert len(world.handler.calls) == 2


@pytest.mark.parametrize("seq", [2**53, 2**63, 2**64 - 1, 2**64, -1, -(2**63)])
def test_out_of_range_seq_is_dropped_without_dispatch(seq: int) -> None:
    world, sent, sid = _session()
    try:
        frame = (
            seal_frame(sent.c2t, sid, seq, "test.echo", "x") if seq >= 0 and seq < 2**64 else None
        )
    except Exception:  # noqa: BLE001 - nonce packing cannot express it; use forged AAD below
        frame = None
    aad = cbor2.dumps({"session_id": sid, "seq": seq, "op": "test.echo"})
    forged = cbor2.dumps({"kind": "frame", "aad": aad, "ct": bytes(40)})
    for body in [b for b in (frame, forged) if b is not None]:
        r = world.server.process(body)
        assert r.response is None
    assert world.handler.calls == []
    _alive(world, sent, sid, 0)


@pytest.mark.parametrize("bad", [1.0, 1.5, "1", b"\x01", None, True, [1], {"a": 1}])
def test_non_integer_seq_is_dropped(bad: object) -> None:
    world, sent, sid = _session()
    aad = cbor2.dumps({"session_id": sid, "seq": bad, "op": "test.echo"})
    r = world.server.process(cbor2.dumps({"kind": "frame", "aad": aad, "ct": bytes(40)}))
    assert r.response is None and world.handler.calls == []
    _alive(world, sent, sid, 0)


def test_backwards_seq_after_gap_and_after_rejections() -> None:
    world, sent, sid = _session()
    _alive(world, sent, sid, 10)
    for seq in (9, 10, 0, 5):
        assert (
            world.server.process(seal_frame(sent.c2t, sid, seq, "test.echo", "x")).response is None
        )
    # a rejected frame must not advance the counter: 11 is still accepted
    assert _alive(world, sent, sid, 11).ok


def test_bad_authentication_does_not_burn_the_sequence_number() -> None:
    world, sent, sid = _session()
    good = seal_frame(sent.c2t, sid, 5, "test.echo", "x")
    env = uncbor(good)
    env["ct"] = env["ct"][:-1] + bytes([env["ct"][-1] ^ 1])
    assert world.server.process(cbor(env)).response is None
    assert _alive(world, sent, sid, 5).ok  # the genuine frame still works


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17])
def test_truncated_ciphertext_is_dropped(n: int) -> None:
    world, sent, sid = _session()
    env = uncbor(seal_frame(sent.c2t, sid, 1, "test.echo", "x"))
    env["ct"] = env["ct"][:n]
    assert world.server.process(cbor(env)).response is None
    assert world.handler.calls == []
    _alive(world, sent, sid, 1)


def test_truncated_open_ciphertext_and_enc_are_dropped() -> None:
    world = make_world()
    sent = world.open_session()
    env = uncbor(sent.body)
    for key, cut in (("ct", 5), ("ct", 0), ("enc", 31), ("enc", 0)):
        e = dict(env)
        e[key] = e[key][:cut]
        r = world.server.process(cbor(e))
        assert r.response is None
    # the pre-key must still be usable after failed (non-authentic) attempts? record outcome
    r = world.server.process(sent.body)
    assert str(r.outcome) in {"SESSION_OPENED", "PREKEY_UNKNOWN", "OPEN_FAILED"}


def test_open_with_unknown_prekey_id_and_wrong_instance() -> None:
    world = make_world()
    sent = world.open_session()
    assert world.server.process(retarget_open(sent, prekey_id=999)).response is None
    assert world.server.process(retarget_open(sent, instance_id="00" * 16)).response is None
    raw_aad = dict(sent.aad, prekey_id=-1)
    raw = cbor2.dumps({"kind": "open", "aad": cbor2.dumps(raw_aad), "enc": sent.enc, "ct": sent.ct})
    assert world.server.process(raw).response is None
    raw_aad = dict(sent.aad, prekey_id=2**64)
    raw = cbor2.dumps({"kind": "open", "aad": cbor2.dumps(raw_aad), "enc": sent.enc, "ct": sent.ct})
    assert world.server.process(raw).response is None


def test_frame_to_wrong_session_id_and_after_close() -> None:
    world, sent, sid = _session()
    assert (
        world.server.process(seal_frame(sent.c2t, bytes(16), 1, "test.echo", "x")).response is None
    )
    assert (
        world.server.process(seal_frame(sent.c2t, sid[:15], 1, "test.echo", "x")).response is None
    )
    r = world.server.process(seal_frame(sent.c2t, sid, 1, "close", None))
    assert r.response is not None
    assert world.server.process(seal_frame(sent.c2t, sid, 2, "test.echo", "x")).response is None


def test_two_sessions_same_client_route_do_not_cross() -> None:
    world, sent_a, sid_a = _session()
    _s2, opened_b = world.established()  # replaces or coexists
    assert opened_b.session_id != sid_a
    r = world.server.process(seal_frame(sent_a.c2t, sid_a, 1, "test.echo", "x"))
    # either the old session was replaced (dropped) or is live; both fine, but never a response
    # under the new session's key
    if r.response is not None:
        assert read_frame_result(r.response.body, sent_a.t2c).ok


@pytest.mark.parametrize(
    "garbage",
    [
        b"",
        b"\x00",
        b"\xff" * 10,
        b"\xa0",
        b"\xbf\xff",
        b"\x9f\xff",
        cbor({"kind": "open"}),
        cbor({"kind": "frame"}),
        cbor({"kind": 1}),
        cbor([1, 2]),
        b"\xa1" * 5000,
        cbor("x" * 70000),
    ],
)
def test_garbage_messages_never_raise(garbage: bytes) -> None:
    world, sent, sid = _session()
    r = world.server.process(garbage)
    assert r.response is None
    _alive(world, sent, sid, 0)
