"""T-06 criterion 2: identity nonce and launcher nonce (API.md §A, D-017 CI-7)."""

import hashlib
import string

import pytest

from teecustody.attest import identity_nonce, launcher_nonce

KEY = bytes(range(32))


def test_identity_nonce_is_sha256_of_the_raw_public_key() -> None:
    assert identity_nonce(KEY) == hashlib.sha256(KEY).digest()


def test_launcher_nonce_is_64_lowercase_hex_characters() -> None:
    nonce = launcher_nonce(identity_nonce(KEY))

    assert nonce == hashlib.sha256(KEY).hexdigest()
    assert len(nonce) == 64
    assert set(nonce) <= set(string.digits + "abcdef")


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_identity_nonce_rejects_a_key_of_the_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match=r"^IDENTITY_KEY_LENGTH$"):
        identity_nonce(bytes(length))


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_launcher_nonce_rejects_a_nonce_of_the_wrong_length(length: int) -> None:
    with pytest.raises(ValueError, match=r"^IDENTITY_NONCE_LENGTH$"):
        launcher_nonce(bytes(length))
