"""T-10: the open-request replay cache (INC-2-API §4.9; R-6; SR-4, SR-14)."""

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
