"""Gateway resource limits (INC-2-API §6; SR-4)."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayLimits:
    """Request size, page size, rate, concurrency and CORS limits of the reference gateway."""

    max_request_bytes: int = 65536
    max_bundles: int = 16
    max_page: int = 32
    per_source_rate: float = 20.0  # tokens/s per source address
    per_source_burst: int = 40
    global_rate: float = 500.0
    global_burst: int = 1000
    max_concurrency: int = 64
    max_sources_tracked: int = 10_000  # LRU of per-source buckets
    cors_origins: tuple[str, ...] = ()  # empty = same-origin only (no CORS headers at all)
    per_source_max_in_flight: int = 8  # 1..max_concurrency; concurrent requests per source key
    body_read_timeout_s: float = 10.0  # 1.0..60.0; total deadline to receive the request body
    header_read_timeout_s: float = 10.0  # 1.0..60.0; total deadline for one request's header block
    max_connections: int = 512  # >= max_concurrency; open connections per process, any state
    max_header_bytes: int = 8192  # 1024..12288; raw_path + query_string + header names and values
    max_header_count: int = 64  # 16..256; headers per request
    write_timeout_s: float = 30.0  # 1.0..60.0; deadline for the peer to drain buffered output
