"""Reference gateway HTTP application (INC-2-API §6): an untrusted relay of opaque bytes."""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import fastapi
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response

from notes_gateway.limits import GatewayLimits

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json(status: int, obj: object) -> Response:
    body = json.dumps(obj, separators=(",", ":"))
    return Response(body, status_code=status, media_type="application/json")


def create_app(
    queue: RelayQueue,
    *,
    limits: GatewayLimits = GatewayLimits(),
    rng: Callable[[int], bytes] = os.urandom,
    clock: Callable[[], float] = time.monotonic,
) -> fastapi.FastAPI:
    """Build the gateway ASGI app over `queue` (routes: INC-2-API §6)."""
    app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/bundles")
    async def list_bundles(request: Request) -> Response:
        bundles = await run_in_threadpool(queue.list_bundles, limits.max_bundles)
        items = [
            {"instance_id": b.instance_id, "bundle": _b64url(b.bundle)}
            for b in bundles[: limits.max_bundles]
        ]
        return _json(200, {"bundles": items})

    @app.post("/requests/{instance}")
    async def publish_request(request: Request) -> Response:
        instance: str = request.path_params["instance"]
        body = await request.body()
        request_id = rng(16).hex()
        await run_in_threadpool(queue.publish_request, instance, request_id, body)
        return _json(202, {"request_id": request_id})

    return app
