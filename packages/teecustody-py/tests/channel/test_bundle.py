"""T-22: `build_bundle` (INC-2-API §4.7, §3.1; spec §5.1; R-2)."""

import pytest

from teecustody.attest.ports import AttestationToken
from teecustody.channel import build_bundle
from teecustody.channel.codec import PreKeyEntry, decode_bundle
from teecustody.channel.prekeys import PreKeyPublic
from teecustody.wire import DecodeLimits

INSTANCE_ID = "fedcba9876543210" * 2
IK_PUB = bytes(range(32))
TOKEN = AttestationToken(
    value="aGVhZGVy.cGF5bG9hZA.c2ln", issued_at=1_800_000_000, expires_at=1_800_003_600
)
PUBLISHED_AT = 1_800_000_123
DECODE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)


def prekey(prekey_id: int) -> PreKeyPublic:
    return PreKeyPublic(
        id=prekey_id,
        pub=bytes([prekey_id % 256]) * 32,
        not_after=1_800_003_600 + prekey_id,
        sig=bytes([255 - prekey_id % 256]) * 64,
    )


def build(prekeys: list[PreKeyPublic]) -> bytes:
    return build_bundle(
        instance_id=INSTANCE_ID,
        token=TOKEN,
        ik_pub=IK_PUB,
        prekeys=prekeys,
        published_at=PUBLISHED_AT,
    )


def test_c8_bundle_round_trips_through_the_codec() -> None:
    prekeys = [prekey(3), prekey(7), prekey(42)]

    bundle = decode_bundle(build(prekeys), DECODE_LIMITS)

    assert bundle.instance_id == INSTANCE_ID
    assert bundle.token == TOKEN.value
    assert bundle.ik_pub == IK_PUB
    assert bundle.published_at == PUBLISHED_AT
    assert bundle.prekeys == tuple(
        PreKeyEntry(id=p.id, pub=p.pub, not_after=p.not_after, sig=p.sig) for p in prekeys
    )


def test_c8_bundle_with_the_wire_maximum_of_256_entries_is_built() -> None:
    bundle = decode_bundle(build([prekey(i) for i in range(256)]), DECODE_LIMITS)

    assert [p.id for p in bundle.prekeys] == list(range(256))


@pytest.mark.parametrize("count", [0, 257])
def test_c8_entry_count_outside_1_to_256_is_refused(count: int) -> None:
    with pytest.raises(ValueError, match=r"\APREKEYS_RANGE\Z"):
        build([prekey(i) for i in range(count)])


@pytest.mark.parametrize("ids", [[2, 1], [1, 1], [0, 5, 3]])
def test_c8_entries_out_of_ascending_id_order_are_refused(ids: list[int]) -> None:
    with pytest.raises(ValueError, match=r"\APREKEY_ID_RANGE\Z"):
        build([prekey(i) for i in ids])
