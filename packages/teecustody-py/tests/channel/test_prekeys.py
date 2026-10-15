"""T-22: `PreKeyStore` (INC-2-API §4.7; spec §4, §5.1; SR-14, NFR-3, SR-4)."""

import math

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from teecustody.channel import IdentityKey, PreKeyStore, hpke
from teecustody.channel.codec import prekey_signing_message
from teecustody.config import ChannelParams
from teecustody.secrets import Secret

INSTANCE_ID = "0123456789abcdef" * 2
IMAGE_DIGEST = "sha256:" + "ab" * 32
START = 1_800_000_000.75


class FakeClock:
    def __init__(self, now: float = START) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def capture_private_keys(monkeypatch: pytest.MonkeyPatch) -> list[Secret]:
    """Record every private key the store obtains from `hpke.generate_keypair`."""
    captured: list[Secret] = []
    original = hpke.generate_keypair

    def recording() -> tuple[Secret, bytes]:
        private, public = original()
        captured.append(private)
        return private, public

    monkeypatch.setattr(hpke, "generate_keypair", recording)
    return captured


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


def test_c3_take_returns_the_private_key_once() -> None:
    store = make_store()
    store.top_up()
    entry = store.public_entries()[4]

    private = store.take(entry.id)

    assert type(private) is Secret
    assert len(private) == 32
    derived = X25519PrivateKey.from_private_bytes(private.reveal()).public_key()
    assert derived.public_bytes_raw() == entry.pub
    assert entry.id not in [e.id for e in store.public_entries()]
    with pytest.raises(KeyError) as second:
        store.take(entry.id)
    assert second.value.args == ("PREKEY_UNKNOWN",)


@pytest.mark.parametrize("prekey_id", [10, 2**32 - 1, 2**32, -1])
def test_c3_take_of_an_unknown_id_is_refused(prekey_id: int) -> None:
    store = make_store()
    store.top_up()

    with pytest.raises(KeyError) as excinfo:
        store.take(prekey_id)

    assert excinfo.value.args == ("PREKEY_UNKNOWN",)


@pytest.mark.parametrize("past", [0.0, 0.5, 3600.0])
def test_c3_take_of_an_expired_id_is_refused_and_the_key_is_wiped(
    monkeypatch: pytest.MonkeyPatch, past: float
) -> None:
    captured = capture_private_keys(monkeypatch)
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    clock.now = store.public_entries()[0].not_after + past

    with pytest.raises(KeyError) as excinfo:
        store.take(0)

    assert excinfo.value.args == ("PREKEY_UNKNOWN",)
    assert captured[0].wiped
    assert not any(secret.wiped for secret in captured[1:])
    with pytest.raises(KeyError):
        store.take(0)


def test_c3_take_one_second_before_expiry_succeeds() -> None:
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    clock.now = store.public_entries()[0].not_after - 0.001

    assert len(store.take(0)) == 32


def test_c4_expire_destroys_and_wipes_keys_at_or_past_not_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = capture_private_keys(monkeypatch)
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()  # ids 0..9
    clock.now += 100
    for prekey_id in range(8):
        store.take(prekey_id)
    store.top_up()  # ids 10..17, not_after 100 s later
    clock.now = store.public_entries()[0].not_after  # ids 8, 9 expire exactly now

    assert store.expire() == 2

    assert [e.id for e in store.public_entries()] == list(range(10, 18))
    assert captured[8].wiped
    assert captured[9].wiped
    assert not any(secret.wiped for secret in captured[10:])
    assert store.expire() == 0


def test_c4_public_entries_omit_expired_keys_before_expire_runs() -> None:
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    clock.now = store.public_entries()[0].not_after

    assert store.public_entries() == ()


def test_c4_expired_keys_do_not_count_as_live_for_top_up() -> None:
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    clock.now += 100
    for prekey_id in range(6):
        store.take(prekey_id)
    store.top_up()  # 4 live: no-op
    clock.now = store.public_entries()[0].not_after  # all 4 expire, nothing expired yet

    assert store.top_up() == 10
    assert [e.id for e in store.public_entries()] == list(range(10, 20))


def test_c5_consumed_since_counts_takes_at_or_after_the_given_time() -> None:
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    times = [START + offset for offset in (0.0, 1.0, 1.0, 2.5, 30.0, 59.0, 60.0)]
    for prekey_id, at in enumerate(times):
        clock.now = at
        store.take(prekey_id)

    assert store.consumed_since(START) == 7
    assert store.consumed_since(START - 1) == 7
    assert store.consumed_since(START + 1.0) == 6
    assert store.consumed_since(START + 1.5) == 4
    assert store.consumed_since(START + 59.0) == 2
    assert store.consumed_since(START + 60.0) == 1
    assert store.consumed_since(START + 60.5) == 0


def test_c5_refused_takes_are_not_counted_as_consumed() -> None:
    clock = FakeClock()
    store = make_store(clock=clock)
    store.top_up()
    store.take(0)
    with pytest.raises(KeyError):
        store.take(0)
    with pytest.raises(KeyError):
        store.take(99)
    clock.now = store.public_entries()[0].not_after
    with pytest.raises(KeyError):
        store.take(1)

    assert store.consumed_since(0.0) == 1


def test_c5_consumption_history_keeps_only_the_last_two_hours() -> None:
    clock = FakeClock()
    params = ChannelParams(prekey_batch=2, prekey_low_water=1, prekey_ttl_s=3600)
    store = make_store(clock=clock, params=params)
    store.top_up()  # ids 0, 1
    store.take(0)  # at START
    clock.now = START + 3000
    store.take(1)
    clock.now = START + 3601
    store.top_up()  # ids 2, 3, valid until after START + 7200.001
    clock.now = START + 7200
    store.take(2)  # the START take is exactly 2 h old: kept

    assert store.consumed_since(0.0) == 3

    clock.now = START + 7200.001
    store.take(3)  # the START take is now older than 2 h: trimmed

    assert store.consumed_since(0.0) == 3
    assert store.consumed_since(START + 3000) == 3
