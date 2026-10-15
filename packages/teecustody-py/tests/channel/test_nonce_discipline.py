"""T-23 criteria 1-4, 7: t2c nonce discipline (R-5, D2-16, SR-14; INC-2-API §4.9)."""

import os
from typing import ClassVar

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given, settings
from hypothesis import strategies as st

from teecustody.channel import session as session_module
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


# ---------------------------------------------------------------- criterion 4 (R-5 property)
SEALS_PER_EXAMPLE = 1000


class _SpyAesGcm:
    """Stands in for `AESGCM` inside `teecustody.channel.session`; records every (key, nonce)."""

    calls: ClassVar[list[tuple[bytes, bytes]]] = []
    fail_next: ClassVar[bool] = False

    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        _SpyAesGcm.calls.append((self._key, nonce))
        if _SpyAesGcm.fail_next:
            _SpyAesGcm.fail_next = False
            raise RuntimeError("injected")
        return AESGCM(self._key).encrypt(nonce, data, associated_data)


@settings(max_examples=5, deadline=None)
@given(
    st.lists(
        st.tuples(st.booleans(), st.booleans()),
        min_size=SEALS_PER_EXAMPLE,
        max_size=SEALS_PER_EXAMPLE,
    )
)
def test_no_key_nonce_pair_is_ever_reused_and_the_counter_never_decreases(
    steps: list[tuple[bool, bool]],
) -> None:
    _SpyAesGcm.calls = []
    # (seq, plaintext, bytes the run loop re-published after a failed publish)
    retried: list[tuple[int, bytes, tuple[bytes, bytes]]] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(session_module, "AESGCM", _SpyAesGcm)
        sealer, key = _opened_sealer()
        counter = sealer._next_seq
        for index, (encrypt_fails, publish_fails) in enumerate(steps):
            seq, plaintext = sealer._next_seq, index.to_bytes(2, "big")
            _SpyAesGcm.fail_next = encrypt_fails
            try:
                stored = sealer.seal_frame_result(OP, SESSION_ID, plaintext)
            except RuntimeError:
                assert encrypt_fails
            else:
                assert not encrypt_fails
                assert stored[0] == encode_frame_aad(
                    FrameAad(session_id=SESSION_ID, seq=seq, op=OP)
                )
                if publish_fails:
                    calls_before = len(_SpyAesGcm.calls)
                    # The run loop re-publishes the stored bytes; it never asks for a new seal.
                    resent = stored
                    assert len(_SpyAesGcm.calls) == calls_before
                    retried.append((seq, plaintext, resent))
            assert sealer._next_seq > counter
            counter = sealer._next_seq
    assert len(_SpyAesGcm.calls) == SEALS_PER_EXAMPLE + 1
    assert len(set(_SpyAesGcm.calls)) == len(_SpyAesGcm.calls)
    # After every later seal, each re-sent message still authenticates under the nonce of the seq
    # it was first sealed with, and that nonce was used exactly once.
    for seq, plaintext, (aad_bytes, ct) in retried:
        assert AESGCM(key).decrypt(_nonce(seq), ct, aad_bytes) == plaintext
        assert _SpyAesGcm.calls.count((key, _nonce(seq))) == 1


# ---------------------------------------------------------------- criterion 7
@pytest.mark.parametrize("seq", [0, 1, 255, 256, 2**32, MAX_SEQ])
def test_nonce_is_four_zero_bytes_then_the_seq_as_u64be(seq: int) -> None:
    assert _nonce(seq) == b"\x00" * 4 + seq.to_bytes(8, "big")
    assert len(_nonce(seq)) == 12


def test_nonce_layout_is_pinned_bytewise() -> None:
    assert _nonce(0x0102030405060708 & MAX_SEQ) == bytes.fromhex("000000000002030405060708")


@pytest.mark.parametrize("seq", [-1, -(2**64), 2**53, 2**64])
def test_nonce_rejects_a_seq_outside_zero_to_max_seq(seq: int) -> None:
    with pytest.raises(ValueError, match=r"^SEQ_RANGE$"):
        _nonce(seq)
