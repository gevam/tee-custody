"""SR-14 channel protocol integrity (INC-2, workload side): layouts, schema bounds, replay window,
nonce discipline, principal binding.

Owning tasks: T-07 (layouts, codec), T-10 (ReplayCache), T-23 (T2cSealer, Session), T-28 (principal
binding), T-12/T-24 (support). Expected failure on trunk: NotImplementedError('T-07' | 'T-10' |
'T-23') or NotImplementedError('T-24') for the server-level tests.
"""

import hashlib
import os
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tests.support.channel_doubles import MismatchingOpener

from acc_channel import (
    CLIENT_ID,
    OTHER_CLIENT_ID,
    cbor,
    hpke_info,
    make_world,
    nonce,
    prekey_message,
    read_frame_result,
    read_open_result,
    seal_frame,
    u32,
    uncbor,
)
from acc_support import IMAGE_DIGEST, FakeClock
from teecustody.channel import (
    CloseReason,
    EnvelopeError,
    EnvelopeErrorCode,
    ReplayCache,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
)
from teecustody.channel.codec import (
    FrameAad,
    OpenResultAad,
    decode_bundle,
    decode_open_result_plaintext,
    decode_request,
    prekey_signing_message,
)
from teecustody.channel.codec import hpke_info as codec_hpke_info
from teecustody.config import BoundaryLimits
from teecustody.secrets import Secret, SecretError
from teecustody.wire import DecodeLimits

IID = "0123456789abcdef" * 2
PUB = bytes(range(32))
BUNDLE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)
OPEN_RESULT_LIMITS = DecodeLimits(max_bytes=32768, max_depth=16, max_items=4096)


# ---------------------------------------------------------------- byte layouts (section 2)
def test_SR14_prekey_signing_message_matches_the_independent_layout() -> None:
    # Given the section-2 definition m = H("prekey-v1" || instance || u32 id || pub || u64 t || digest)
    expected = prekey_message(IID, 7, PUB, 1_900_003_600)
    # When the library builds it
    got = prekey_signing_message(IID, 7, PUB, 1_900_003_600, IMAGE_DIGEST)
    # Then they are byte-identical (32 bytes; the preimage is exactly 156 bytes)
    assert got == expected and len(got) == 32


def test_SR14_hpke_info_matches_the_independent_layout() -> None:
    # Given ascii("tee-chan-v1") || H(IK_pub) || u32be(prekey_id)
    ik = bytes(range(1, 33))
    expected = b"tee-chan-v1" + hashlib.sha256(ik).digest() + u32(5)
    # When the library builds it
    got = codec_hpke_info(ik, 5)
    # Then they are identical and 47 bytes long
    assert got == expected == hpke_info(ik, 5) and len(got) == 47


@pytest.mark.parametrize(
    "kwargs",
    [
        {"instance_id": IID.upper()},
        {"instance_id": IID[:-1]},
        {"instance_id": IID + "0"},
        {"instance_id": IID + "\n"},
        {"prekey_id": 2**32},
        {"prekey_id": -1},
        {"pub": PUB[:-1]},
        {"pub": PUB + b"\x00"},
        {"not_after": 2**53},
        {"not_after": -1},
        {"image_digest": "sha256:" + "a" * 63},
        {"image_digest": "sha256:" + "A" * 64},
        {"image_digest": "sha256:" + "a" * 64 + "\n"},
        {"image_digest": "sha1:" + "a" * 64},
    ],
    ids=lambda k: next(iter(k)) + "=" + str(next(iter(k.values())))[:12].replace("\n", "NL"),
)
def test_SR14_prekey_signing_message_rejects_every_width_or_range_violation(
    kwargs: dict[str, Any],
) -> None:
    # Given a builder input with exactly one violation
    args: dict[str, Any] = {
        "instance_id": IID,
        "prekey_id": 1,
        "pub": PUB,
        "not_after": 1,
        "image_digest": IMAGE_DIGEST,
    }
    args.update(kwargs)
    # When building the signing message
    # Then it raises ValueError("<FIELD>_RANGE") before hashing
    with pytest.raises(ValueError, match=r"_RANGE$"):
        prekey_signing_message(**args)


@pytest.mark.parametrize(
    ("ik", "pid"),
    [(bytes(31), 0), (bytes(33), 0), (bytes(32), 2**32), (bytes(32), -1)],
)
def test_SR14_hpke_info_rejects_width_and_range_violations(ik: bytes, pid: int) -> None:
    with pytest.raises(ValueError, match=r"_RANGE$"):
        codec_hpke_info(ik, pid)


# ---------------------------------------------------------------- schema bounds (R-1, R-2, R-3)
def _bundle(**override: Any) -> bytes:
    prekeys = override.pop(
        "prekeys",
        [{"id": i, "pub": PUB, "not_after": 1_900_003_600, "sig": bytes(64)} for i in (0, 1, 2)],
    )
    doc: dict[str, Any] = {
        "instance_id": IID,
        "token": "aaa.bbb.ccc",
        "IK_pub": bytes(32),
        "published_at": 1_900_000_000,
        "prekeys": prekeys,
    }
    doc.update(override)
    return cbor(doc)


def test_SR14_a_well_formed_bundle_decodes() -> None:
    # Given a canonical bundle with ascending pre-key ids
    decoded = decode_bundle(_bundle(), BUNDLE_LIMITS)
    # Then it decodes with its entries intact (positive control for the rejections below)
    assert decoded.instance_id == IID and [p.id for p in decoded.prekeys] == [0, 1, 2]


def _prekey(i: int, **kw: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"id": i, "pub": PUB, "not_after": 1_900_003_600, "sig": bytes(64)}
    entry.update(kw)
    return entry


@pytest.mark.parametrize(
    "data",
    [
        _bundle(instance_id=IID + "\n"),
        _bundle(instance_id=IID.upper()),
        _bundle(published_at=2**53),
        _bundle(prekeys=[_prekey(0, not_after=2**53)]),
        _bundle(prekeys=[_prekey(1), _prekey(0)]),
        _bundle(prekeys=[_prekey(0), _prekey(0)]),
        _bundle(prekeys=[]),
        _bundle(prekeys=[_prekey(i) for i in range(257)]),
        _bundle(prekeys=[_prekey(0, sig=bytes(63))]),
        _bundle(prekeys=[_prekey(0, pub=bytes(31))]),
        _bundle(prekeys=[_prekey(2**32)]),
        _bundle(token=""),
        _bundle(IK_pub=bytes(31)),
        _bundle(extra=1),
        b"\xa0",
    ],
    ids=[
        "id-newline",
        "id-uppercase",
        "published-over-max",
        "not-after-over-max",
        "ids-unsorted",
        "ids-duplicate",
        "no-prekeys",
        "too-many-prekeys",
        "short-sig",
        "short-pub",
        "id-over-uint32",
        "empty-token",
        "short-ik",
        "unknown-key",
        "empty-map",
    ],
)
def test_SR14_bundle_decoder_rejects_schema_violations(data: bytes) -> None:
    # Given a bundle violating one schema rule
    # When decoded
    # Then the only outcome is EnvelopeError(INVALID)
    with pytest.raises(EnvelopeError) as exc:
        decode_bundle(data, BUNDLE_LIMITS)
    assert exc.value.code is EnvelopeErrorCode.INVALID


def test_SR14_oversize_request_is_rejected_before_decoding() -> None:
    # Given a body one byte over max_request_bytes
    limits = BoundaryLimits()
    with pytest.raises(EnvelopeError) as exc:
        decode_request(b"\x00" * (limits.max_request_bytes + 1), limits)
    # Then TOO_LARGE
    assert exc.value.code is EnvelopeErrorCode.TOO_LARGE


def test_SR14_open_result_ok_if_and_only_if_session_id_present() -> None:
    # Given plaintexts that violate R-3 after authentication
    rid = bytes(16)
    with_session = OpenResultAad(session_id=bytes(16), request_id=rid)
    without = OpenResultAad(session_id=None, request_id=rid)
    ok_pt = cbor({"ok": True, "payload": None})
    err_pt = cbor({"ok": False, "error": "INTERNAL"})
    # Then ok:true with a nil session, and ok:false with a session, are invalid
    with pytest.raises(EnvelopeError):
        decode_open_result_plaintext(ok_pt, without, OPEN_RESULT_LIMITS)
    with pytest.raises(EnvelopeError):
        decode_open_result_plaintext(err_pt, with_session, OPEN_RESULT_LIMITS)
    # And the consistent combinations decode
    assert decode_open_result_plaintext(ok_pt, with_session, OPEN_RESULT_LIMITS).ok is True
    assert decode_open_result_plaintext(err_pt, without, OPEN_RESULT_LIMITS).error == "INTERNAL"


# ---------------------------------------------------------------- replay window (R-6)
def test_SR14_replay_entry_lives_exactly_as_long_as_the_message_could_be_accepted() -> None:
    # Given a cache with skew 300 s
    clock, skew = FakeClock(), 300
    cache = ReplayCache(skew_s=skew, max_entries=100, clock=clock)
    now = int(clock.now)
    # When a message with the latest acceptable timestamp (now + skew - 1) is recorded
    timestamp = now + skew - 1
    cache.record(CLIENT_ID, b"r" * 16, timestamp)
    assert cache.seen(CLIENT_ID, b"r" * 16)
    # Then its identical replay is still caught when the message could still pass the skew check
    clock.now = now + 2 * skew - 2
    assert cache.seen(CLIENT_ID, b"r" * 16)
    # And at exactly timestamp + skew the entry is still present
    clock.now = timestamp + skew
    assert cache.seen(CLIENT_ID, b"r" * 16)
    # And one second later it is purged
    clock.now = timestamp + skew + 1
    assert not cache.seen(CLIENT_ID, b"r" * 16)


def test_SR14_replay_key_is_the_pair_client_and_request() -> None:
    # Given a recorded pair
    clock = FakeClock()
    cache = ReplayCache(skew_s=300, max_entries=10, clock=clock)
    cache.record(CLIENT_ID, b"r" * 16, int(clock.now))
    # Then neither another client with the same request id nor the same client with another id matches
    assert not cache.seen(OTHER_CLIENT_ID, b"r" * 16)
    assert not cache.seen(CLIENT_ID, b"s" * 16)


# ---------------------------------------------------------------- nonce discipline (R-5, D2-16)
def test_SR14_t2c_nonce_zero_is_used_exactly_once_for_the_open_result() -> None:
    # Given a sealer that owns sk_t2c
    key, sid, rid = os.urandom(32), os.urandom(16), os.urandom(16)
    sealer = T2cSealer(Secret(key))
    # When a frame result is requested before the open_result
    with pytest.raises(SessionReject) as early:
        sealer.seal_frame_result("test.echo", sid, b"x")
    # Then it is refused (it would have used nonce 0)
    assert early.value.code is SessionRejectCode.USED
    # When the open_result is sealed
    aad_bytes, ct = sealer.seal_open_result(OpenResultAad(session_id=sid, request_id=rid), b"ok")
    # Then it authenticates under nonce 0 with AAD seq 0
    assert uncbor(aad_bytes)["seq"] == 0
    assert AESGCM(key).decrypt(nonce(0), ct, aad_bytes) == b"ok"
    # And sealing a second open_result is refused
    with pytest.raises(SessionReject) as second:
        sealer.seal_open_result(OpenResultAad(session_id=sid, request_id=rid), b"again")
    assert second.value.code is SessionRejectCode.USED


def test_SR14_one_thousand_seals_never_reuse_a_nonce_and_the_counter_never_decreases() -> None:
    # Given a sealer after its open_result
    key, sid = os.urandom(32), os.urandom(16)
    sealer = T2cSealer(Secret(key))
    sealer.seal_open_result(OpenResultAad(session_id=sid, request_id=bytes(16)), b"ok")
    # When 1,000 frame results are sealed
    seen: list[int] = []
    for i in range(1000):
        aad_bytes, ct = sealer.seal_frame_result("test.echo", sid, i.to_bytes(4, "big"))
        aad = uncbor(aad_bytes)
        seen.append(aad["seq"])
        # Then each ciphertext authenticates under exactly the nonce its AAD seq names
        assert AESGCM(key).decrypt(nonce(aad["seq"]), ct, aad_bytes) == i.to_bytes(4, "big")
        assert aad["session_id"] == sid and aad["op"] == "test.echo"
    # And the seqs are 1..1000: unique, increasing, never 0
    assert seen == list(range(1, 1001))


def test_SR14_a_wiped_sealer_cannot_seal() -> None:
    # Given a sealer whose keys were wiped (session closed)
    sealer = T2cSealer(Secret(os.urandom(32)))
    sealer.wipe()
    # Then sealing fails rather than using a zeroed key
    with pytest.raises((SecretError, SessionReject)):
        sealer.seal_open_result(OpenResultAad(session_id=None, request_id=bytes(16)), b"x")


def _table(clock: FakeClock, closes: list[Any], max_sessions: int = 4) -> SessionTable:
    return SessionTable(
        instance_id=IID,
        max_sessions=max_sessions,
        idle_timeout_s=900,
        evict_min_idle_s=60,
        on_close=lambda info, reason: closes.append((info.session_id, reason)),
        clock=clock,
    )


def test_SR14_c2t_sequence_is_checked_before_decryption_and_failures_change_nothing() -> None:
    # Given a session with a known c2t key
    clock, closes = FakeClock(), []
    table = _table(clock, closes)
    key, sid = os.urandom(32), os.urandom(16)
    session = table.create(
        session_id=sid,
        client_id=CLIENT_ID,
        sk_c2t=Secret(key),
        t2c=T2cSealer(Secret(os.urandom(32))),
    )

    def frame(seq: int, good: bool = True) -> tuple[FrameAad, bytes, bytes]:
        aad_bytes = cbor({"session_id": sid, "seq": seq, "op": "test.echo"})
        ct = AESGCM(key if good else bytes(32)).encrypt(nonce(seq), b"p", aad_bytes)
        return FrameAad(session_id=sid, seq=seq, op="test.echo"), aad_bytes, ct

    # When seq 5 arrives with a bad tag
    aad, aad_bytes, ct = frame(5, good=False)
    with pytest.raises(SessionReject) as bad:
        session.open_c2t(aad, aad_bytes, ct, clock())
    assert bad.value.code is SessionRejectCode.AUTH_FAILED
    # Then seq 5 is still acceptable afterwards (state unchanged) and decrypts correctly
    aad, aad_bytes, ct = frame(5)
    assert session.open_c2t(aad, aad_bytes, ct, clock()).reveal() == b"p"
    # And a replay of seq 5, even with garbage ciphertext, is rejected on the sequence alone
    with pytest.raises(SessionReject) as replay:
        session.open_c2t(aad, aad_bytes, b"\x00" * 32, clock())
    assert replay.value.code is SessionRejectCode.SEQ_REJECTED


# ---------------------------------------------------------------- principal binding (R-4)
def test_SR14_enroll_with_a_victims_id_as_reply_route_does_not_touch_the_victim() -> None:
    # Given an established session for CLIENT_ID (the victim)
    world = make_world()
    victim, victim_open = world.established(route=CLIENT_ID)
    assert victim_open.session_id is not None
    # When an attacker enrols with AAD client_id = the victim's id
    attack = world.enroll(route=CLIENT_ID)
    result = world.server.process(attack.body)
    # Then the opener receives no claimed identity
    assert world.opener.requests[-1].claimed_client_id is None  # type: ignore[attr-defined]
    # And the victim's session is neither replaced nor closed
    assert world.sessions.get(victim_open.session_id) is not None
    assert (victim_open.session_id, CloseReason.REPLACED) not in world.closes
    # And the open_result goes only to the AAD route and authenticates for the enrolling client
    assert result.response is not None and result.response.client_id == CLIENT_ID
    opened = read_open_result(result.response.body, attack.t2c)
    assert opened.ok and opened.session_id is not None
    minted = world.opener.enrolling.minted[-1]  # type: ignore[attr-defined]
    assert opened.payload == {"client_id": minted} and minted != CLIENT_ID
    # And the new session belongs to the minted principal, never to the route
    session = world.sessions.get(opened.session_id)
    assert session is not None and session.client_id == minted
    # And logs name only the minted principal for that open
    opened_logs = [f for _l, o, f in world.logger.calls if o == "SESSION_OPENED"]
    assert [f["client_id"] for f in opened_logs] == [CLIENT_ID, minted]
    # And the victim can still use its session
    reply = world.server.process(seal_frame(victim.c2t, victim_open.session_id, 0, "test.echo", 1))
    assert reply.response is not None and read_frame_result(reply.response.body, victim.t2c).ok


def test_SR14_a_principal_that_differs_from_the_claim_creates_no_session() -> None:
    # Given an opener that accepts every open but returns a different principal
    world = make_world(opener=MismatchingOpener("d5" * 16))
    # When a client claims CLIENT_ID
    sent = world.open_session()
    result = world.server.process(sent.body)
    # Then the answer is an INTERNAL refusal with no session id
    assert result.response is not None
    opened = read_open_result(result.response.body, sent.t2c)
    assert not opened.ok and opened.session_id is None and opened.error == "INTERNAL"
    # And no session exists, and the opener was told the open was aborted
    request = world.opener.requests[0]  # type: ignore[attr-defined]
    assert world.sessions.get(request.session_id) is None
    assert (request.session_id, CloseReason.OPEN_ABORTED) in world.opener.closed_calls  # type: ignore[attr-defined]
    # And the audit counts it as a rejected open
    assert world.flush_aggregates() == {"OPEN_REJECTED": 1}


def test_SR14_repeated_enrols_on_a_victims_route_never_close_the_victims_session() -> None:
    # Given a victim session and an attacker who enrols twice on the victim's route
    world = make_world()
    _victim, victim_open = world.established(route=CLIENT_ID)
    assert victim_open.session_id is not None
    for _ in range(2):
        assert world.server.process(world.enroll(route=CLIENT_ID).body).response is not None
    # Then the victim's session survives both
    assert world.sessions.get(victim_open.session_id) is not None
    assert {r for _s, r in world.closes} <= {CloseReason.EVICTED}
