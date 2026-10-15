"""T-22: `PreKeyStore` (INC-2-API §4.7; spec §4, §5.1; SR-14, NFR-3, SR-4)."""

import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from teecustody.channel import IdentityKey, PreKeyStore
from teecustody.channel.codec import prekey_signing_message
from teecustody.config import ChannelParams

INSTANCE_ID = "0123456789abcdef" * 2
IMAGE_DIGEST = "sha256:" + "ab" * 32
START = 1_800_000_000.75


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_store(
    *,
    clock: FakeClock | None = None,
    identity: IdentityKey | None = None,
    params: ChannelParams | None = None,
) -> PreKeyStore:
    return PreKeyStore(
        instance_id=INSTANCE_ID,
        identity=identity or IdentityKey.generate(),
        image_digest=IMAGE_DIGEST,
        params=params or ChannelParams(prekey_batch=10, prekey_low_water=3, prekey_ttl_s=600),
        clock=clock or FakeClock(),
    )


def test_c1_top_up_on_an_empty_store_generates_a_signed_batch() -> None:
    identity = IdentityKey.generate()
    store = make_store(identity=identity)

    generated = store.top_up()

    entries = store.public_entries()
    assert generated == 10
    assert [e.id for e in entries] == list(range(10))
    assert {e.not_after for e in entries} == {math.floor(START) + 600}
    assert len({e.pub for e in entries}) == 10
    public = Ed25519PublicKey.from_public_bytes(identity.public_bytes())
    for e in entries:
        assert len(e.pub) == 32
        message = prekey_signing_message(INSTANCE_ID, e.id, e.pub, e.not_after, IMAGE_DIGEST)
        public.verify(e.sig, message)


def test_c2_top_up_is_a_no_op_at_or_above_low_water_and_refills_below_it() -> None:
    store = make_store()
    store.top_up()
    for prekey_id in range(7):  # 3 live == low_water
        store.take(prekey_id)

    assert store.top_up() == 0
    assert len(store.public_entries()) == 3

    store.take(7)  # 2 live < low_water

    assert store.top_up() == 8
    entries = store.public_entries()
    assert [e.id for e in entries] == [8, 9, *range(10, 18)]
