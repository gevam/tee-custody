"""T-06 criterion 1: the workload identity key (IK)."""

from teecustody.channel import IdentityKey


def test_generated_keys_are_raw_32_byte_and_distinct() -> None:
    first = IdentityKey.generate()
    second = IdentityKey.generate()

    assert len(first.public_bytes()) == 32
    assert len(second.public_bytes()) == 32
    assert first.public_bytes() != second.public_bytes()


def test_repr_is_redacted_and_carries_no_key_bytes() -> None:
    key = IdentityKey.generate()
    public = key.public_bytes()

    text = repr(key)

    assert text == "IdentityKey(<redacted>)"
    assert str(key) == "IdentityKey(<redacted>)"
    assert public.hex() not in text
    assert public.hex() not in str(key)
