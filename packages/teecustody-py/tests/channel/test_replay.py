"""T-10: the open-request replay cache (INC-2-API §4.9; R-6; SR-4, SR-14)."""

import time

import pytest

from teecustody.channel import ReplayCache

CLIENT = "c1" * 16
OTHER_CLIENT = "c2" * 16
RID = b"r" * 16
OTHER_RID = b"s" * 16
T0 = 1_700_000_000


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_empty_cache_has_seen_nothing_and_a_recorded_pair_is_seen_by_its_exact_key() -> None:
    clock = Clock()
    cache = ReplayCache(skew_s=300, max_entries=10, clock=clock)

    assert not cache.seen(CLIENT, RID)

    cache.record(CLIENT, RID, T0)

    assert cache.seen(CLIENT, RID)
    assert not cache.seen(CLIENT, OTHER_RID)
    assert not cache.seen(OTHER_CLIENT, RID)


def test_entry_lives_until_timestamp_plus_skew_inclusive_and_is_purged_one_second_later() -> None:
    skew = 300
    clock = Clock()
    cache = ReplayCache(skew_s=skew, max_entries=10, clock=clock)
    timestamp = T0 + skew - 1
    cache.record(CLIENT, RID, timestamp)

    clock.now = T0 + 2 * skew - 2
    assert cache.seen(CLIENT, RID)

    clock.now = timestamp + skew
    assert cache.seen(CLIENT, RID)
    assert cache._size() == 1

    clock.now = timestamp + skew + 1
    assert not cache.seen(CLIENT, RID)
    assert cache._size() == 0


def _full_cache(clock: Clock) -> ReplayCache:
    cache = ReplayCache(skew_s=300, max_entries=3, clock=clock)
    for n in range(3):
        cache.record(CLIENT, bytes([n]) * 16, T0)
    return cache


def test_full_cache_refuses_a_new_entry_and_keeps_every_live_one() -> None:
    cache = _full_cache(Clock())

    with pytest.raises(OverflowError, match=r"^REPLAY_CACHE_FULL$"):
        cache.record(CLIENT, b"\x09" * 16, T0)

    assert all(cache.seen(CLIENT, bytes([n]) * 16) for n in range(3))
    assert not cache.seen(CLIENT, b"\x09" * 16)
    assert cache._size() == 3


def test_full_cache_accepts_a_new_entry_once_every_entry_has_expired() -> None:
    clock = Clock()
    cache = _full_cache(clock)

    clock.now = T0 + 300 + 1
    cache.record(CLIENT, b"\x09" * 16, int(clock.now))

    assert cache.seen(CLIENT, b"\x09" * 16)
    assert cache._size() == 1


def test_a_long_run_with_a_moving_clock_is_fast_and_stays_within_max_entries() -> None:
    skew, max_entries = 1_000, 20_000
    clock = Clock()
    cache = ReplayCache(skew_s=skew, max_entries=max_entries, clock=clock)
    largest = 0

    started = time.perf_counter()
    for n in range(100_000):
        clock.now = T0 + n // 10
        cache.record(CLIENT, n.to_bytes(16, "big"), T0 + n // 10)
        largest = max(largest, cache._size())
    elapsed = time.perf_counter() - started

    assert elapsed < 2.0
    assert largest <= max_entries
    assert cache.seen(CLIENT, (99_999).to_bytes(16, "big"))
    assert not cache.seen(CLIENT, (0).to_bytes(16, "big"))


@pytest.mark.parametrize("skew_s", [0, -1])
def test_skew_below_one_is_refused(skew_s: int) -> None:
    with pytest.raises(ValueError, match=r"^SKEW_RANGE$"):
        ReplayCache(skew_s=skew_s, max_entries=10, clock=Clock())


@pytest.mark.parametrize("max_entries", [0, -1])
def test_max_entries_below_one_is_refused(max_entries: int) -> None:
    with pytest.raises(ValueError, match=r"^MAX_ENTRIES_RANGE$"):
        ReplayCache(skew_s=300, max_entries=max_entries, clock=Clock())


def test_the_smallest_valid_values_are_accepted() -> None:
    clock = Clock()
    cache = ReplayCache(skew_s=1, max_entries=1, clock=clock)
    cache.record(CLIENT, RID, T0)

    assert cache.seen(CLIENT, RID)
