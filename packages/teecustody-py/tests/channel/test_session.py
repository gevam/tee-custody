"""T-23 criteria 5-6: c2t frames are accepted once, in strictly increasing order (§4.9)."""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.codec import FrameAad, encode_frame_aad
from teecustody.channel.ports import CloseReason, SessionInfo
from teecustody.channel.session import (
    Session,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
    _nonce,
    open_frame,
)
from teecustody.secrets import Secret

INSTANCE_ID = "fedcba9876543210" * 2
CLIENT_ID = "0123456789abcdef" * 2
SESSION_ID = bytes(range(16))
OTHER_SESSION_ID = bytes(range(1, 17))
OP = "test.echo"
T0 = 1_900_000_000.0


class FakeClock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now


def _frame(
    key: bytes, seq: int, *, session_id: bytes = SESSION_ID, plaintext: bytes = b"p"
) -> tuple[FrameAad, bytes, bytes]:
    aad = FrameAad(session_id=session_id, seq=seq, op=OP)
    aad_bytes = encode_frame_aad(aad)
    return aad, aad_bytes, AESGCM(key).encrypt(_nonce(seq), plaintext, aad_bytes)


def _session() -> tuple[Session, bytes, FakeClock]:
    clock = FakeClock()
    closes: list[tuple[SessionInfo, CloseReason]] = []
    table = SessionTable(
        instance_id=INSTANCE_ID,
        max_sessions=4,
        idle_timeout_s=900,
        evict_min_idle_s=60,
        on_close=lambda info, reason: closes.append((info, reason)),
        clock=clock,
    )
    key = os.urandom(32)
    session = table.create(
        session_id=SESSION_ID,
        client_id=CLIENT_ID,
        sk_c2t=Secret(key),
        t2c=T2cSealer(Secret(os.urandom(32))),
    )
    return session, key, clock


def _rejected(session: Session, frame: tuple[FrameAad, bytes, bytes], now: float) -> str:
    with pytest.raises(SessionReject) as err:
        session.open_c2t(*frame, now)
    return err.value.code


# ---------------------------------------------------------------- criterion 5
def test_c2t_seqs_must_strictly_increase_and_gaps_are_allowed() -> None:
    session, key, clock = _session()
    assert session.open_c2t(*_frame(key, 0, plaintext=b"zero"), clock()).reveal() == b"zero"
    assert _rejected(session, _frame(key, 0), clock()) is SessionRejectCode.SEQ_REJECTED
    below = (FrameAad(session_id=SESSION_ID, seq=-1, op=OP), b"", b"")
    assert _rejected(session, below, clock()) is SessionRejectCode.SEQ_REJECTED
    assert session.open_c2t(*_frame(key, 5, plaintext=b"five"), clock()).reveal() == b"five"
    assert _rejected(session, _frame(key, 5), clock()) is SessionRejectCode.SEQ_REJECTED
    assert _rejected(session, _frame(key, 4), clock()) is SessionRejectCode.SEQ_REJECTED


def test_a_replayed_seq_is_rejected_before_decryption() -> None:
    session, key, clock = _session()
    aad, aad_bytes, _ct = _frame(key, 0)
    session.open_c2t(*_frame(key, 0), clock())
    garbage = (aad, aad_bytes, b"\x00" * 32)
    assert _rejected(session, garbage, clock()) is SessionRejectCode.SEQ_REJECTED


def test_a_successful_frame_refreshes_last_activity() -> None:
    session, key, _clock = _session()
    assert session.opened_at == T0
    assert session.last_activity == T0
    session.open_c2t(*_frame(key, 0), T0 + 42)
    assert session.last_activity == T0 + 42
    assert session.opened_at == T0


def test_an_aead_failure_is_auth_failed_and_changes_nothing() -> None:
    session, key, _clock = _session()
    forged = _frame(os.urandom(32), 3)
    assert _rejected(session, forged, T0 + 10) is SessionRejectCode.AUTH_FAILED
    assert session.last_activity == T0
    assert session.open_c2t(*_frame(key, 3, plaintext=b"three"), T0 + 20).reveal() == b"three"
    assert session.last_activity == T0 + 20


def test_a_tampered_aad_is_auth_failed() -> None:
    session, key, clock = _session()
    aad, _aad_bytes, ct = _frame(key, 1)
    other_bytes = encode_frame_aad(FrameAad(session_id=SESSION_ID, seq=1, op="test.other"))
    assert _rejected(session, (aad, other_bytes, ct), clock()) is SessionRejectCode.AUTH_FAILED
    assert session.open_c2t(aad, _aad_bytes, ct, clock()).reveal() == b"p"


def test_a_frame_for_another_session_id_is_auth_failed() -> None:
    session, key, clock = _session()
    foreign = _frame(key, 0, session_id=OTHER_SESSION_ID)
    assert _rejected(session, foreign, T0 + 10) is SessionRejectCode.AUTH_FAILED
    assert session.last_activity == T0
    assert session.open_c2t(*_frame(key, 0), clock()).reveal() == b"p"


# ---------------------------------------------------------------- criterion 6
def _open_frame_code(key: Secret, last_seq: int, frame: tuple[FrameAad, bytes, bytes]) -> str:
    with pytest.raises(SessionReject) as err:
        open_frame(key, last_seq, *frame)
    return err.value.code


def test_open_frame_applies_the_same_seq_rules_to_a_free_standing_key() -> None:
    raw = os.urandom(32)
    key = Secret(raw)
    assert open_frame(key, -1, *_frame(raw, 0, plaintext=b"zero")).reveal() == b"zero"
    assert _open_frame_code(key, 0, _frame(raw, 0)) is SessionRejectCode.SEQ_REJECTED
    below = (FrameAad(session_id=SESSION_ID, seq=-1, op=OP), b"", b"")
    assert _open_frame_code(key, 0, below) is SessionRejectCode.SEQ_REJECTED
    assert open_frame(key, 0, *_frame(raw, 5, plaintext=b"five")).reveal() == b"five"
    assert _open_frame_code(key, 5, _frame(raw, 5)) is SessionRejectCode.SEQ_REJECTED


def test_open_frame_checks_seq_before_decrypting() -> None:
    raw = os.urandom(32)
    aad, aad_bytes, _ct = _frame(raw, 2)
    garbage = (aad, aad_bytes, b"\x00" * 32)
    assert _open_frame_code(Secret(raw), 2, garbage) is SessionRejectCode.SEQ_REJECTED
    assert _open_frame_code(Secret(raw), 1, garbage) is SessionRejectCode.AUTH_FAILED


def test_open_frame_under_the_wrong_key_is_auth_failed() -> None:
    frame = _frame(os.urandom(32), 0)
    assert _open_frame_code(Secret(os.urandom(32)), -1, frame) is SessionRejectCode.AUTH_FAILED


def test_open_frame_auth_failure_carries_no_library_cause() -> None:
    with pytest.raises(SessionReject) as err:
        open_frame(Secret(os.urandom(32)), -1, *_frame(os.urandom(32), 0))
    assert str(err.value) == "AUTH_FAILED"
    assert err.value.__cause__ is None
    assert err.value.__suppress_context__
