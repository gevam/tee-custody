"""Reference gateway HTTP application (INC-2-API §6): an untrusted relay of opaque bytes."""

from __future__ import annotations

import asyncio
import base64
import functools
import ipaddress
import json
import math
import os
import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import fastapi
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from notes_gateway.limits import GatewayLimits
from teecustody.obs import get_logger
from teecustody.queue import CURSOR_PATTERN, QueueError, QueueErrorCode

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue

# Equal to teecustody.channel.codec.HEX32_PATTERN; not imported from there so that the
# gateway's import graph never contains the CBOR codec. fullmatch only (R-7).
_HEX32_PATTERN = re.compile(r"[0-9a-f]{32}")
_CONTENT_LENGTH_PATTERN = re.compile(r"[0-9]{1,19}")
# C0 and C1 controls and DEL anywhere in the decoded path (§6 control-character rule); search.
_CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_OCTET_STREAM = "application/octet-stream"
_QUEUE_ERRORS: dict[QueueErrorCode, tuple[int, str]] = {
    QueueErrorCode.INVALID_ARGUMENT: (400, "INVALID_ARGUMENT"),
    QueueErrorCode.NOT_FOUND: (404, "UNKNOWN_INSTANCE"),
    QueueErrorCode.UNAVAILABLE: (503, "UNAVAILABLE"),
}
_INTERNAL = (500, "INTERNAL")
_HTTP_ERRORS: dict[int, tuple[int, str]] = {
    404: (404, "NOT_FOUND"),
    405: (405, "METHOD_NOT_ALLOWED"),
}
_OUTCOME_KEY = "notes_gateway.outcome"
_LOG = get_logger("gateway")
_SECURITY_HEADERS = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]

Endpoint = Callable[[Request], Awaitable[Response]]

_INT_LIMITS = (
    "max_request_bytes",
    "max_bundles",
    "max_page",
    "per_source_burst",
    "global_burst",
    "max_concurrency",
    "max_sources_tracked",
    "per_source_max_in_flight",
)
_RATE_LIMITS = ("per_source_rate", "global_rate")
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_PORT = r"(?::(?P<port>[1-9][0-9]{0,4}))?"
# Browser-serialised origins (RFC 6454): https with a lowercase DNS host, or loopback http.
# fullmatch only (R-7).
_HTTPS_ORIGIN_PATTERN = re.compile(rf"https://{_DNS_LABEL}(?:\.{_DNS_LABEL})*{_PORT}")
_LOOPBACK_ORIGIN_PATTERN = re.compile(rf"http://(?:localhost|127\.0\.0\.1|\[::1\]){_PORT}")
_DEFAULT_PORTS = {"https": "443", "http": "80"}


def _validate(limits: GatewayLimits) -> None:
    """API-TL TL-4: numeric limits first, then the CORS allow-list."""
    for name in _INT_LIMITS:
        value = getattr(limits, name)
        if type(value) is not int or value <= 0:
            raise ValueError("INVALID_LIMITS")
    for name in _RATE_LIMITS:
        value = getattr(limits, name)
        if not _positive_number(value):
            raise ValueError("INVALID_LIMITS")
    if limits.per_source_max_in_flight > limits.max_concurrency:
        raise ValueError("INVALID_LIMITS")
    for timeout_s in (limits.body_read_timeout_s, limits.header_read_timeout_s):
        if not _positive_number(timeout_s) or not 1.0 <= timeout_s <= 60.0:
            raise ValueError("INVALID_LIMITS")
    ranges = (
        (limits.max_connections, limits.max_concurrency, math.inf),
        (limits.max_header_bytes, 1024, 12288),
        (limits.max_header_count, 16, 256),
    )
    if not all(type(value) is int and low <= value <= high for value, low, high in ranges):
        raise ValueError("INVALID_LIMITS")
    origins: object = limits.cors_origins
    if type(origins) is not tuple or not all(_valid_origin(o) for o in origins):
        raise ValueError("INVALID_CORS_ORIGIN")


def _positive_number(value: object) -> bool:
    """A finite positive int or float; bool is refused."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(value) and value > 0


def _valid_origin(origin: object) -> bool:
    if type(origin) is not str:
        return False
    match = _HTTPS_ORIGIN_PATTERN.fullmatch(origin) or _LOOPBACK_ORIGIN_PATTERN.fullmatch(origin)
    if match is None:
        return False
    port = match.group("port")
    scheme = origin.split(":", 1)[0]
    return port is None or (int(port) <= 65535 and port != _DEFAULT_PORTS[scheme])


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json(status: int, obj: object) -> Response:
    body = json.dumps(obj, separators=(",", ":"))
    return Response(body, status_code=status, media_type="application/json")


class _Outcome:
    """The request's log outcome; INTERNAL unless a layer records another."""

    __slots__ = ("code",)

    def __init__(self) -> None:
        self.code = "INTERNAL"


def _refuse(scope: Scope, status: int, code: str) -> Response:
    """Record `code` as the request outcome and answer the §6 error body."""
    scope[_OUTCOME_KEY].code = code
    return _json(status, {"code": code})


class _Invalid(Exception):
    """A route argument or body broke the §6 rules (400 INVALID_ARGUMENT)."""


class _BodyTimeout(Exception):
    """The request body did not arrive within `body_read_timeout_s` (408 REQUEST_TIMEOUT)."""


def _guarded(endpoint: Endpoint) -> Endpoint:
    """Map every failure to a stable §6 code; the cause never reaches the body or the logs."""

    @functools.wraps(endpoint)
    async def wrapper(request: Request) -> Response:
        try:
            response = await endpoint(request)
        except _Invalid:
            status, code = 400, "INVALID_ARGUMENT"
        except _BodyTimeout:
            response = _refuse(request.scope, 408, "REQUEST_TIMEOUT")
            response.headers["Connection"] = "close"
            return response
        except QueueError as exc:
            status, code = _QUEUE_ERRORS.get(exc.code, _INTERNAL)
        except Exception:  # noqa: BLE001 - the relay answers INTERNAL for any other failure
            status, code = _INTERNAL
        else:
            request.scope[_OUTCOME_KEY].code = "OK"
            return response
        return _refuse(request.scope, status, code)

    return wrapper


def _check(pattern: re.Pattern[str], value: str) -> str:
    if not pattern.fullmatch(value):
        raise _Invalid
    return value


async def _read_body(request: Request, max_bytes: int, timeout_s: float) -> bytes:
    """The raw body; _Invalid if its headers or length break the §6 rules. Never decoded."""
    if request.headers.getlist("content-type") != [_OCTET_STREAM]:
        raise _Invalid
    lengths = request.headers.getlist("content-length")
    if len(lengths) != 1:
        raise _Invalid
    declared = int(_check(_CONTENT_LENGTH_PATTERN, lengths[0]))
    if not 1 <= declared <= max_bytes:
        raise _Invalid
    body = bytearray()
    try:
        async with asyncio.timeout(timeout_s):
            async for chunk in request.stream():
                body += chunk
                if len(body) > declared:
                    raise _Invalid
    except ClientDisconnect:
        raise _Invalid from None
    except TimeoutError:
        raise _BodyTimeout from None
    if len(body) != declared:
        raise _Invalid
    return bytes(body)


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
        self._sources: OrderedDict[str, _Bucket] = OrderedDict()  # least recently used first

    def admit(self, source: str) -> int | None:
        """None if admitted (one token spent from each bucket), else the Retry-After seconds."""
        now = self._clock()
        self._global.refill(now)
        retry = self._global.retry_after()
        if retry is not None:
            return retry
        bucket = self._source_bucket(source, now)
        bucket.refill(now)
        retry = bucket.retry_after()
        if retry is not None:
            return retry
        self._global.tokens -= 1.0
        bucket.tokens -= 1.0
        return None

    def _source_bucket(self, source: str, now: float) -> _Bucket:
        bucket = self._sources.get(source)
        if bucket is not None:
            self._sources.move_to_end(source)
            return bucket
        bucket = _Bucket(self._limits.per_source_rate, self._limits.per_source_burst, now)
        self._sources[source] = bucket
        if len(self._sources) > self._limits.max_sources_tracked:
            self._sources.popitem(last=False)
        return bucket


class _Guard:
    """Outer ASGI layer: response headers, concurrency, rate limits, header limits and CORS
    preflight."""

    def __init__(self, app: ASGIApp, *, limits: GatewayLimits, clock: Callable[[], float]) -> None:
        self._app = app
        self._max_concurrency = limits.max_concurrency
        self._per_source_max = limits.per_source_max_in_flight
        self._in_flight = 0
        self._in_flight_by_source: dict[str, int] = {}  # no zero entries; <= max_concurrency keys
        self._limiter = _Limiter(limits, clock)
        self._cors_origins = frozenset(limits.cors_origins)
        self._max_header_bytes = limits.max_header_bytes
        self._max_header_count = limits.max_header_count

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        outcome = _Outcome()
        scope = {**scope, _OUTCOME_KEY: outcome}
        try:
            await self._handle(scope, receive, send)
        finally:
            _LOG.info("GATEWAY_" + outcome.code)

    async def _handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = Headers(scope=scope)
        origins = headers.getlist("origin")
        cors = len(origins) == 1 and origins[0] in self._cors_origins
        cors_headers = _cors_headers(origins[0]) if cors else []
        send = _with_headers(send, [*_SECURITY_HEADERS, *cors_headers])
        source = _source_key(scope.get("client"))
        held = self._in_flight_by_source.get(source, 0)
        if held >= self._per_source_max or self._in_flight >= self._max_concurrency:
            await _rate_limited(scope, 1)(scope, receive, send)
            return
        self._in_flight += 1
        self._in_flight_by_source[source] = held + 1
        try:
            await self._admitted(scope, receive, send, source, cors=cors)
        finally:
            self._in_flight -= 1
            self._release(source)

    async def _admitted(
        self, scope: Scope, receive: Receive, send: Send, source: str, *, cors: bool
    ) -> None:
        retry = self._limiter.admit(source)
        if retry is not None:
            await _rate_limited(scope, retry)(scope, receive, send)
            return
        if not self._headers_within_limits(scope):
            await _refuse(scope, 400, "INVALID_ARGUMENT")(scope, receive, send)
            return
        if _CONTROL_CHARACTER_PATTERN.search(scope["path"]):
            await _refuse(scope, 404, "NOT_FOUND")(scope, receive, send)
            return
        method, headers = scope["method"], Headers(scope=scope)
        if cors and method == "OPTIONS" and "access-control-request-method" in headers:
            scope[_OUTCOME_KEY].code = "OK"
            await _PREFLIGHT(scope, receive, send)
            return
        await self._app(scope, receive, send)

    def _headers_within_limits(self, scope: Scope) -> bool:
        """§6 header limits, measured on the parsed scope so segmentation cannot change them."""
        headers: list[tuple[bytes, bytes]] = scope["headers"]
        size = len(scope["raw_path"]) + len(scope["query_string"])
        size += sum(len(name) + len(value) for name, value in headers)
        return size <= self._max_header_bytes and len(headers) <= self._max_header_count

    def _release(self, source: str) -> None:
        remaining = self._in_flight_by_source[source] - 1
        if remaining:
            self._in_flight_by_source[source] = remaining
        else:
            del self._in_flight_by_source[source]


def _source_key(client: tuple[str, int] | None) -> str:
    """§6 source key: IPv4 address, IPv4-mapped IPv6 as IPv4, other IPv6 by /64, else "unknown"."""
    try:
        address = ipaddress.ip_address(client[0]) if client else None
    except ValueError:
        address = None
    if address is None:
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address.packed, 64), strict=False))
    return str(address)


def _cors_headers(origin: str) -> list[tuple[bytes, bytes]]:
    return [(b"access-control-allow-origin", origin.encode("latin-1")), (b"vary", b"Origin")]


def _with_headers(send: Send, extra: list[tuple[bytes, bytes]]) -> Send:
    """Wrap `send` so the response start message also carries `extra` headers."""

    async def wrapped(message: Message) -> None:
        if message["type"] == "http.response.start":
            message = {**message, "headers": [*message["headers"], *extra]}
        await send(message)

    return wrapped


_PREFLIGHT = Response(
    status_code=200,
    headers={
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Content-Type",
    },
)


def _rate_limited(scope: Scope, retry_after: int) -> Response:
    response = _refuse(scope, 429, "RATE_LIMITED")
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
    _validate(limits)
    app = fastapi.FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(_Guard, limits=limits, clock=clock)
    app.router.redirect_slashes = False

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> Response:
        status, code = _HTTP_ERRORS.get(exc.status_code, _INTERNAL)
        return _refuse(request.scope, status, code)

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
        instance = _check(_HEX32_PATTERN, request.path_params["instance"])
        body = await _read_body(request, limits.max_request_bytes, limits.body_read_timeout_s)
        request_id = rng(16).hex()
        await run_in_threadpool(queue.publish_request, instance, request_id, body)
        return _json(202, {"request_id": request_id})

    @app.get("/responses/{client}")
    @_guarded
    async def pull_responses(request: Request) -> Response:
        client = _check(_HEX32_PATTERN, request.path_params["client"])
        cursors = request.query_params.getlist("after")
        if len(cursors) > 1:
            raise _Invalid
        after = _check(CURSOR_PATTERN, cursors[0]) if cursors else None
        page = await run_in_threadpool(queue.pull_responses, client, after, limits.max_page)
        items = [
            {"request_id": r.request_id, "body": _b64url(r.body)}
            for r in page.responses[: limits.max_page]
        ]
        return _json(200, {"responses": items, "next": page.next})

    return app
