"""Reference gateway HTTP application (INC-2-API §6). Wave-0 stub: T-14 implements it."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import fastapi

from notes_gateway.limits import GatewayLimits

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue


def create_app(
    queue: RelayQueue,
    *,
    limits: GatewayLimits = GatewayLimits(),
    rng: Callable[[int], bytes] = os.urandom,
    clock: Callable[[], float] = time.monotonic,
) -> fastapi.FastAPI:
    """Build the gateway ASGI app over `queue` (routes: INC-2-API §6)."""
    raise NotImplementedError("T-14")
