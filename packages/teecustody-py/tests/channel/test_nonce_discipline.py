"""T-23 criteria 1-4, 7: t2c nonce discipline (R-5, D2-16, SR-14; INC-2-API §4.9)."""

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.codec import OpenResultAad, encode_open_result_aad
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
