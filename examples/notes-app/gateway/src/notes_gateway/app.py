"""Reference gateway HTTP application (INC-2-API §6): an untrusted relay of opaque bytes."""

from __future__ import annotations

import base64
import functools
import json
import math
import os
import re
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import fastapi
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from notes_gateway.limits import GatewayLimits
from teecustody.queue import CURSOR_PATTERN, QueueError, QueueErrorCode

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue

# Equal to teecustody.channel.codec.HEX32_PATTERN; not imported from there so that the
# gateway's import graph never contains the CBOR codec. fullmatch only (R-7).
_HEX32_PATTERN = re.compile(r"[0-9a-f]{32}")
_CONTENT_LENGTH_PATTERN = re.compile(r"[0-9]{1,19}")
_OCTET_STREAM = "application/octet-stream"
_QUEUE_ERRORS: dict[QueueErrorCode, tuple[int, str]] = {
    QueueErrorCode.INVALID_ARGUMENT: (400, "INVALID_ARGUMENT"),
    QueueErrorCode.NOT_FOUND: (404, "UNKNOWN_INSTANCE"),
    QueueErrorCode.UNAVAILABLE: (503, "UNAVAILABLE"),
}
_INTERNAL = (500, "INTERNAL")

Endpoint = Callable[[Request], Awaitable[Response]]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json(status: int, obj: object) -> Response:
    body = json.dumps(obj, separators=(",", ":"))
    return Response(body, status_code=status, media_type="application/json")


def _invalid() -> Response:
    return _json(400, {"code": "INVALID_ARGUMENT"})


def _guarded(endpoint: Endpoint) -> Endpoint:
    """Map every failure to a stable §6 code; the cause never reaches the body or the logs."""

    @functools.wraps(endpoint)
    async def wrapper(request: Request) -> Response:
        try:
            return await endpoint(request)
        except QueueError as exc:
            status, code = _QUEUE_ERRORS.get(exc.code, _INTERNAL)
        except Exception:  # noqa: BLE001 - the relay answers INTERNAL for any other failure
            status, code = _INTERNAL
        return _json(status, {"code": code})

    return wrapper


async def _read_body(request: Request, max_bytes: int) -> bytes | None:
    """The raw body, or None if its headers or length break the §6 rules; never decoded."""
    if request.headers.getlist("content-type") != [_OCTET_STREAM]:
        return None
    lengths = request.headers.getlist("content-length")
    if len(lengths) != 1 or not _CONTENT_LENGTH_PATTERN.fullmatch(lengths[0]):
        return None
    declared = int(lengths[0])
    if not 1 <= declared <= max_bytes:
        return None
    body = bytearray()
    try:
        async for chunk in request.stream():
            body += chunk
            if len(body) > declared:
                return None
    except ClientDisconnect:
        return None
    return bytes(body) if len(body) == declared else None


class _Bucket:
    """A token bucket: `rate` tokens/s from the injected clock, capacity `burst`."""

    __slots__ = ("burst", "rate", "stamp", "tokens")

    def __init__(self, rate: float, burst: int, now: float) -> None:
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.stamp = now

    def refill(self, now: float) -> None:
        self.tokens = min(float(self.burst), self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now

    def retry_after(self) -> int | None:
        """None if a token is available, else whole seconds until one is (at least 1)."""
        if self.tokens >= 1.0:
            return None
        return max(1, math.ceil((1.0 - self.tokens) / self.rate))


class _Limiter:
    """Global bucket, then a per-source bucket; a token is spent only when both admit."""

    def __init__(self, limits: GatewayLimits, clock: Callable[[], float]) -> None:
        self._limits = limits
        self._clock = clock
        self._global = _Bucket(limits.global_rate, limits.global_burst, clock())
        self._sources: dict[str, _Bucket] = {}

    def admit(self, source: str) -> int | None:
        """None if admitted (one token spent from each bucket), else the Retry-After seconds."""
        now = self._clock()
        self._global.refill(now)
        retry = self._global.retry_after()
        if retry is not None:
            return retry
        bucket = self._sources.get(source)
        if bucket is None:
            bucket = _Bucket(self._limits.per_source_rate, self._limits.per_source_burst, now)
            self._sources[source] = bucket
        bucket.refill(now)
        retry = bucket.retry_after()
        if retry is not None:
            return retry
        self._global.tokens -= 1.0
        bucket.tokens -= 1.0
        return None


class _Guard:
    """Outer ASGI layer: concurrency limit, then rate limits, before any route runs."""

    def __init__(self, app: ASGIApp, *, limits: GatewayLimits, clock: Callable[[], float]) -> None:
        self._app = app
        self._max_concurrency = limits.max_concurrency
        self._in_flight = 0
        self._limiter = _Limiter(limits, clock)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if self._in_flight >= self._max_concurrency:
            await _rate_limited(1)(scope, receive, send)
            return
        client = scope.get("client")
        retry = self._limiter.admit(client[0] if client else "unknown")
        if retry is not None:
            await _rate_limited(retry)(scope, receive, send)
            return
        self._in_flight += 1
        try:
            await self._app(scope, receive, send)
        finally:
            self._in_flight -= 1


def _rate_limited(retry_after: int) -> Response:
    response = _json(429, {"code": "RATE_LIMITED"})
    response.headers["Retry-After"] = str(retry_after)
    return response


def create_app(
    queue: RelayQueue,
    *,
    limits: GatewayLimits = GatewayLimits(),
    rng: Callable[[int], bytes] = os.urandom,
    clock: Callable[[], float] = time.monotonic,
) -> fastapi.FastAPI:
    """Build the gateway ASGI app over `queue` (routes: INC-2-API §6)."""
    app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_Guard, limits=limits, clock=clock)

    @app.get("/bundles")
    @_guarded
    async def list_bundles(request: Request) -> Response:
        bundles = await run_in_threadpool(queue.list_bundles, limits.max_bundles)
        items = [
            {"instance_id": b.instance_id, "bundle": _b64url(b.bundle)}
            for b in bundles[: limits.max_bundles]
        ]
        return _json(200, {"bundles": items})

    @app.post("/requests/{instance}")
    @_guarded
    async def publish_request(request: Request) -> Response:
        instance: str = request.path_params["instance"]
        if not _HEX32_PATTERN.fullmatch(instance):
            return _invalid()
        body = await _read_body(request, limits.max_request_bytes)
        if body is None:
            return _invalid()
        request_id = rng(16).hex()
        await run_in_threadpool(queue.publish_request, instance, request_id, body)
        return _json(202, {"request_id": request_id})

    @app.get("/responses/{client}")
    @_guarded
    async def pull_responses(request: Request) -> Response:
        client: str = request.path_params["client"]
        after = request.query_params.get("after")
        if not _HEX32_PATTERN.fullmatch(client):
            return _invalid()
        if after is not None and not CURSOR_PATTERN.fullmatch(after):
            return _invalid()
        page = await run_in_threadpool(queue.pull_responses, client, after, limits.max_page)
        items = [
            {"request_id": r.request_id, "body": _b64url(r.body)}
            for r in page.responses[: limits.max_page]
        ]
        return _json(200, {"responses": items, "next": page.next})

    return app
