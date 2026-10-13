"""Open-request replay cache (INC-2-API §4.9; spec §5.4 step 12; R-6)."""

from collections.abc import Callable


class ReplayCache:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None:
        self._skew_s = skew_s
        self._max_entries = max_entries
        self._clock = clock
        self._expires: dict[tuple[str, bytes], int] = {}

    def seen(self, aad_client_id: str, request_id: bytes) -> bool:
        self._purge()
        return (aad_client_id, request_id) in self._expires

    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None:
        self._purge()
        if len(self._expires) >= self._max_entries:
            raise OverflowError("REPLAY_CACHE_FULL")
        self._expires[(aad_client_id, request_id)] = timestamp + self._skew_s

    def _purge(self) -> None:
        now = self._clock()
        for key, expires_at in list(self._expires.items()):
            if expires_at < now:
                del self._expires[key]

    def _size(self) -> int:
        return len(self._expires)
