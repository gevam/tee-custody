"""T-04 criterion 6: `IdentityKey.sign` signs 32-byte digests only (INC-2-API §4.2, A-1; SR-14)."""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from teecustody.channel import IdentityKey


def test_signature_verifies_under_the_public_key() -> None:
    key = IdentityKey.generate()
    message = b"x" * 32

    signature = key.sign(message)

    assert type(signature) is bytes
    assert len(signature) == 64
    Ed25519PublicKey.from_public_bytes(key.public_bytes()).verify(signature, message)


def test_signature_does_not_verify_under_another_key_or_message() -> None:
    key = IdentityKey.generate()
    signature = key.sign(b"x" * 32)
    public = Ed25519PublicKey.from_public_bytes(key.public_bytes())
    other = Ed25519PublicKey.from_public_bytes(IdentityKey.generate().public_bytes())

    with pytest.raises(InvalidSignature):
        public.verify(signature, b"y" * 32)
    with pytest.raises(InvalidSignature):
        other.verify(signature, b"x" * 32)


def test_signature_covers_the_exact_digest_bytes() -> None:
    key = IdentityKey.generate()
    digest = bytes(range(32))

    signature = key.sign(digest)

    Ed25519PublicKey.from_public_bytes(key.public_bytes()).verify(signature, digest)


@pytest.mark.parametrize("length", [0, 31, 33, 64])
def test_message_that_is_not_32_bytes_is_refused(length: int) -> None:
    with pytest.raises(ValueError, match=r"\AMESSAGE_LENGTH\Z") as excinfo:
        IdentityKey.generate().sign(b"x" * length)

    assert excinfo.value.args == ("MESSAGE_LENGTH",)
