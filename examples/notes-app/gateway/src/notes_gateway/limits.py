"""Gateway resource limits (INC-2-API §6; SR-4)."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayLimits:
    """Request size, page size, rate, concurrency and CORS limits of the reference gateway."""
