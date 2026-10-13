"""T-07: signed and hashed byte layouts (INC-2-API §2; SR-14 layouts, D2-1)."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from teecustody.channel.codec import hpke_info, prekey_signing_message

INSTANCE_ID = "0123456789abcdef" * 2
PUB = bytes(range(32))
IMAGE_DIGEST = "sha256:" + "0f" * 32


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


@pytest.fixture
def no_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("hashed before the range checks")

    monkeypatch.setattr(hashlib, "sha256", refuse)


# ---------------------------------------------------------------- criterion 6
@pytest.mark.parametrize(
    ("prekey_id", "not_after"),
    [(7, 1_900_003_600), (0, 0), (2**32 - 1, 2**53 - 1), (0x01020304, 0x0A0B0C0D0E0F)],
)
def test_prekey_signing_message_is_sha256_of_the_156_byte_preimage(
    prekey_id: int, not_after: int
) -> None:
    preimage = (
        b"prekey-v1"
        + INSTANCE_ID.encode("ascii")
        + _u32(prekey_id)
        + PUB
        + _u64(not_after)
        + IMAGE_DIGEST.encode("ascii")
    )
    assert len(preimage) == 156

    message = prekey_signing_message(INSTANCE_ID, prekey_id, PUB, not_after, IMAGE_DIGEST)

    assert type(message) is bytes
    assert message == hashlib.sha256(preimage).digest()


def test_prekey_signing_message_binds_every_input() -> None:
    base: dict[str, Any] = {
        "instance_id": INSTANCE_ID,
        "prekey_id": 1,
        "pub": PUB,
        "not_after": 2,
        "image_digest": IMAGE_DIGEST,
    }
    variants: list[dict[str, Any]] = [
        {"instance_id": "f" + INSTANCE_ID[1:]},
        {"prekey_id": 2},
        {"pub": bytes(32)},
        {"not_after": 3},
        {"image_digest": "sha256:" + "0e" * 32},
    ]

    messages = {prekey_signing_message(**base)} | {
        prekey_signing_message(**{**base, **variant}) for variant in variants
    }

    assert len(messages) == 1 + len(variants)


SIGNING_VIOLATIONS: dict[str, tuple[dict[str, Any], str]] = {
    "instance-id-uppercase": ({"instance_id": INSTANCE_ID.upper()}, "INSTANCE_ID_RANGE"),
    "instance-id-31": ({"instance_id": INSTANCE_ID[:31]}, "INSTANCE_ID_RANGE"),
    "instance-id-33": ({"instance_id": INSTANCE_ID + "0"}, "INSTANCE_ID_RANGE"),
    "instance-id-newline": ({"instance_id": INSTANCE_ID + "\n"}, "INSTANCE_ID_RANGE"),
    "instance-id-bytes": ({"instance_id": INSTANCE_ID.encode()}, "INSTANCE_ID_RANGE"),
    "prekey-id-2^32": ({"prekey_id": 2**32}, "PREKEY_ID_RANGE"),
    "prekey-id-negative": ({"prekey_id": -1}, "PREKEY_ID_RANGE"),
    "prekey-id-bool": ({"prekey_id": True}, "PREKEY_ID_RANGE"),
    "pub-31": ({"pub": PUB[:31]}, "PUB_RANGE"),
    "pub-33": ({"pub": PUB + b"\x00"}, "PUB_RANGE"),
    "pub-text": ({"pub": "p" * 32}, "PUB_RANGE"),
    "not-after-2^53": ({"not_after": 2**53}, "NOT_AFTER_RANGE"),
    "not-after-negative": ({"not_after": -1}, "NOT_AFTER_RANGE"),
    "not-after-bool": ({"not_after": False}, "NOT_AFTER_RANGE"),
    "image-digest-63-hex": ({"image_digest": "sha256:" + "a" * 63}, "IMAGE_DIGEST_RANGE"),
    "image-digest-65-hex": ({"image_digest": "sha256:" + "a" * 65}, "IMAGE_DIGEST_RANGE"),
    "image-digest-uppercase": ({"image_digest": "sha256:" + "A" * 64}, "IMAGE_DIGEST_RANGE"),
    "image-digest-newline": ({"image_digest": IMAGE_DIGEST + "\n"}, "IMAGE_DIGEST_RANGE"),
    "image-digest-sha1": ({"image_digest": "sha1:" + "a" * 64}, "IMAGE_DIGEST_RANGE"),
}


@pytest.mark.usefixtures("no_hashing")
@pytest.mark.parametrize(
    ("override", "message"), SIGNING_VIOLATIONS.values(), ids=SIGNING_VIOLATIONS.keys()
)
def test_prekey_signing_message_rejects_each_violation_before_hashing(
    override: dict[str, Any], message: str
) -> None:
    args: dict[str, Any] = {
        "instance_id": INSTANCE_ID,
        "prekey_id": 1,
        "pub": PUB,
        "not_after": 1,
        "image_digest": IMAGE_DIGEST,
    }

    with pytest.raises(ValueError, match=f"^{message}$"):
        prekey_signing_message(**{**args, **override})


# ---------------------------------------------------------------- criterion 7
IK_PUB = bytes(range(1, 33))


@pytest.mark.parametrize("prekey_id", [5, 0, 2**32 - 1, 0x01020304])
def test_hpke_info_is_proto_then_ik_hash_then_u32_prekey_id(prekey_id: int) -> None:
    info = hpke_info(IK_PUB, prekey_id)

    assert type(info) is bytes
    assert len(info) == 47
    assert info == b"tee-chan-v1" + hashlib.sha256(IK_PUB).digest() + _u32(prekey_id)


HPKE_INFO_VIOLATIONS: dict[str, tuple[Any, Any, str]] = {
    "ik-pub-31": (IK_PUB[:31], 0, "IK_PUB_RANGE"),
    "ik-pub-33": (IK_PUB + b"\x00", 0, "IK_PUB_RANGE"),
    "ik-pub-empty": (b"", 0, "IK_PUB_RANGE"),
    "ik-pub-bytearray": (bytearray(IK_PUB), 0, "IK_PUB_RANGE"),
    "prekey-id-2^32": (IK_PUB, 2**32, "PREKEY_ID_RANGE"),
    "prekey-id-negative": (IK_PUB, -1, "PREKEY_ID_RANGE"),
    "prekey-id-bool": (IK_PUB, True, "PREKEY_ID_RANGE"),
}


@pytest.mark.usefixtures("no_hashing")
@pytest.mark.parametrize(
    ("ik_pub", "prekey_id", "message"),
    HPKE_INFO_VIOLATIONS.values(),
    ids=HPKE_INFO_VIOLATIONS.keys(),
)
def test_hpke_info_rejects_each_violation_before_hashing(
    ik_pub: Any, prekey_id: Any, message: str
) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        hpke_info(ik_pub, prekey_id)
