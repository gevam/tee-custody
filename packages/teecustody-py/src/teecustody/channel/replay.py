"""Open-request replay cache (INC-2-API §4.9; spec §5.4 step 12; R-6)."""

from collections.abc import Callable


class ReplayCache:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None:
        self._entries: set[tuple[str, bytes]] = set()

    def seen(self, aad_client_id: str, request_id: bytes) -> bool:
        return (aad_client_id, request_id) in self._entries

    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None:
        self._entries.add((aad_client_id, request_id))
