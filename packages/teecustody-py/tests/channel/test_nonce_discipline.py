"""T-23 criteria 1-4, 7: t2c nonce discipline (R-5, D2-16, SR-14; INC-2-API §4.9)."""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.codec import (
    MAX_SEQ,
    FrameAad,
    OpenResultAad,
    encode_frame_aad,
    encode_open_result_aad,
)
from teecustody.channel.session import SessionReject, SessionRejectCode, T2cSealer, _nonce
from teecustody.secrets import Secret

SESSION_ID = bytes(range(16))
REQUEST_ID = bytes(range(16, 32))
OPEN_AAD = OpenResultAad(session_id=SESSION_ID, request_id=REQUEST_ID)
OP = "test.echo"


def _sealer() -> tuple[T2cSealer, bytes]:
    key = os.urandom(32)
    return T2cSealer(Secret(key)), key


# ---------------------------------------------------------------- criterion 1
def test_open_result_is_sealed_under_nonce_zero() -> None:
    sealer, key = _sealer()
    aad_bytes, ct = sealer.seal_open_result(OPEN_AAD, b"opened")
    assert aad_bytes == encode_open_result_aad(OPEN_AAD)
    assert AESGCM(key).decrypt(_nonce(0), ct, aad_bytes) == b"opened"


def test_a_second_open_result_is_refused_as_used() -> None:
    sealer, _key = _sealer()
    sealer.seal_open_result(OPEN_AAD, b"opened")
    with pytest.raises(SessionReject) as err:
        sealer.seal_open_result(OPEN_AAD, b"again")
    assert err.value.code is SessionRejectCode.USED


def test_a_frame_result_before_the_open_result_is_refused_as_used() -> None:
    sealer, key = _sealer()
    with pytest.raises(SessionReject) as err:
        sealer.seal_frame_result(OP, SESSION_ID, b"early")
    assert err.value.code is SessionRejectCode.USED
    aad_bytes, ct = sealer.seal_open_result(OPEN_AAD, b"opened")
    assert AESGCM(key).decrypt(_nonce(0), ct, aad_bytes) == b"opened"


# ---------------------------------------------------------------- criterion 2
def test_an_exception_inside_the_open_result_seal_burns_nonce_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sealer, _key = _sealer()

    def explode(self: AESGCM, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        raise RuntimeError("injected")

    with monkeypatch.context() as patch:
        patch.setattr(AESGCM, "encrypt", explode)
        with pytest.raises(RuntimeError, match="injected"):
            sealer.seal_open_result(OPEN_AAD, b"opened")
    with pytest.raises(SessionReject) as err:
        sealer.seal_open_result(OPEN_AAD, b"opened")
    assert err.value.code is SessionRejectCode.USED


# ---------------------------------------------------------------- criterion 3
def _opened_sealer() -> tuple[T2cSealer, bytes]:
    sealer, key = _sealer()
    sealer.seal_open_result(OPEN_AAD, b"opened")
    return sealer, key


def test_frame_results_use_seqs_one_two_three_in_order() -> None:
    sealer, key = _opened_sealer()
    for seq in (1, 2, 3):
        aad_bytes, ct = sealer.seal_frame_result(OP, SESSION_ID, b"frame %d" % seq)
        assert aad_bytes == encode_frame_aad(FrameAad(session_id=SESSION_ID, seq=seq, op=OP))
        assert AESGCM(key).decrypt(_nonce(seq), ct, aad_bytes) == b"frame %d" % seq


def test_the_last_seq_is_max_seq_and_the_next_is_exhausted() -> None:
    sealer, key = _opened_sealer()
    sealer._next_seq = MAX_SEQ
    aad_bytes, ct = sealer.seal_frame_result(OP, SESSION_ID, b"last")
    assert AESGCM(key).decrypt(_nonce(MAX_SEQ), ct, aad_bytes) == b"last"
    with pytest.raises(SessionReject) as err:
        sealer.seal_frame_result(OP, SESSION_ID, b"beyond")
    assert err.value.code is SessionRejectCode.EXHAUSTED


def test_a_counter_beyond_max_seq_is_exhausted() -> None:
    sealer, _key = _opened_sealer()
    sealer._next_seq = MAX_SEQ + 1
    with pytest.raises(SessionReject) as err:
        sealer.seal_frame_result(OP, SESSION_ID, b"beyond")
    assert err.value.code is SessionRejectCode.EXHAUSTED
