"""Open-request replay cache (INC-2-API §4.9; spec §5.4 step 12; R-6)."""

import heapq
from collections.abc import Callable

_Key = tuple[str, bytes]


class ReplayCache:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None:
        if skew_s < 1:
            raise ValueError("SKEW_RANGE")
        if max_entries < 1:
            raise ValueError("MAX_ENTRIES_RANGE")
        self._skew_s = skew_s
        self._max_entries = max_entries
        self._clock = clock
        self._expires: dict[_Key, int] = {}
        self._by_expiry: list[tuple[int, _Key]] = []

    def seen(self, aad_client_id: str, request_id: bytes) -> bool:
        self._purge()
        return (aad_client_id, request_id) in self._expires

    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None:
        self._purge()
        if len(self._expires) >= self._max_entries:
            raise OverflowError("REPLAY_CACHE_FULL")
        key = (aad_client_id, request_id)
        expires_at = timestamp + self._skew_s
        current = self._expires.get(key)
        if current is not None and current >= expires_at:
            return
        self._expires[key] = expires_at
        heapq.heappush(self._by_expiry, (expires_at, key))

    def _purge(self) -> None:
        now = self._clock()
        while self._by_expiry and self._by_expiry[0][0] < now:
            expires_at, key = heapq.heappop(self._by_expiry)
            if self._expires[key] == expires_at:
                del self._expires[key]

    def _size(self) -> int:
        return len(self._expires)
