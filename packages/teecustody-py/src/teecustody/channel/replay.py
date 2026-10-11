"""Open-request replay cache (INC-2-API §4.9; spec §5.4 step 12; R-6). Bodies belong to T-10."""

from collections.abc import Callable


class ReplayCache:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None:
        raise NotImplementedError("T-10")

    def seen(self, aad_client_id: str, request_id: bytes) -> bool:
        raise NotImplementedError("T-10")

    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None:
        raise NotImplementedError("T-10")
