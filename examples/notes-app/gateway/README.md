# notes-gateway — reference queue gateway

An **untrusted** HTTP relay between browsers and the workload's queue (INC-2-API §6; FR-5, SR-1, SR-3,
SR-4; D-003). It is an example, not a product. A host can replace it with any gateway that implements the same
HTTP contract.

The gateway relays opaque bytes. It holds no keys, authenticates nobody, and never decodes, logs or echoes a
request or response body. A route id is a routing hint, not an identity. Only the channel inside the TEE
authenticates a client.

```python
import uvicorn

from notes_gateway import GatewayLimits, create_app
from notes_gateway.server import uvicorn_config

limits = GatewayLimits()
app = create_app(queue, limits=limits)  # queue: any teecustody.queue.RelayQueue
uvicorn.Server(uvicorn_config(app, limits=limits, host="127.0.0.1", port=8080)).run()
```

Run the gateway under uvicorn only through `notes_gateway.server.uvicorn_config`, and pass it the same `limits`
given to `create_app` (see "Server hardening" below).

## Routes

| Route | Request | Success | Errors |
|---|---|---|---|
| `GET /bundles` | no body | `200 {"bundles":[{"instance_id":"<32hex>","bundle":"<b64url>"}]}` (at most `max_bundles`) | 503, 500 |
| `POST /requests/{instance}` | `Content-Type: application/octet-stream`, `Content-Length` required, 1..`max_request_bytes` raw envelope bytes, no `Transfer-Encoding` | `202 {"request_id":"<32hex>"}` (relay id minted by the gateway) | 400, 404 `UNKNOWN_INSTANCE`, 503, 500 |
| `GET /responses/{client}?after=<cursor>` | `after` optional | `200 {"responses":[{"request_id":"<32hex>","body":"<b64url>"}],"next":"<cursor>"\|null}` (at most `max_page`) | 400, 503, 500 |
| any request over a limit | — | — | `429 {"code":"RATE_LIMITED"}` with `Retry-After: <int s>` |
| request body not received within `body_read_timeout_s` | — | — | `408 {"code":"REQUEST_TIMEOUT"}` with `Connection: close` |
| other path / method, or a control character in the path | — | — | `404 {"code":"NOT_FOUND"}` / `405 {"code":"METHOD_NOT_ALLOWED"}` |

- `b64url` is RFC 4648 §5 base64url without padding. `next: null` means "omit `after` next time".
- `{instance}` and `{client}` must be exactly 32 lowercase hex characters. `after` must match
  `[A-Za-z0-9_-]{1,128}` and appear at most once. Both are checked by full match on the decoded value, so
  uppercase hex, or 31 or 33 characters, is a `400`, and so is a cursor with a trailing `%0A`. No queue call
  is made.
- A decoded path containing any C0 or C1 control character or DEL (U+0000–U+001F, U+007F–U+009F), such as
  `/bundles%0A`, is a `404 NOT_FOUND` before routing, with no queue call.
- The body is read as a stream and refused with `400` as soon as it exceeds `Content-Length`. A missing,
  repeated or non-decimal `Content-Length`, a length outside 1..`max_request_bytes`, a body shorter than
  declared, or a `Content-Type` other than exactly `application/octet-stream` (parameters included) is a `400`.
  The whole body must arrive within `body_read_timeout_s` (a total deadline, not per chunk). Otherwise the
  answer is `408 REQUEST_TIMEOUT` with `Connection: close`, and nothing is published.
- An unknown client route returns `200` with an empty page, never an error, so route probing reveals nothing.
- JSON is compact (`separators=(",", ":")`) with `Content-Type: application/json`. There are no OpenAPI or
  docs routes, and no trailing-slash redirects.

## Error bodies

Every error body is exactly `{"code":"<CODE>"}`:

| Status | Code | When |
|---|---|---|
| 400 | `INVALID_ARGUMENT` | bad route id, cursor, headers or body; any `Transfer-Encoding` (with `Connection: close`); a header block over `max_header_bytes` or `max_header_count`; a request the HTTP parser rejects (malformed or oversized header block, missing `Host`, non-HTTP bytes); queue `INVALID_ARGUMENT` |
| 404 | `UNKNOWN_INSTANCE` | queue `NOT_FOUND` (no live bundle for the instance) |
| 404 | `NOT_FOUND` | unknown path |
| 404 | `NOT_FOUND` | control character in the decoded path |
| 405 | `METHOD_NOT_ALLOWED` | unknown method on a known path |
| 408 | `REQUEST_TIMEOUT` | body not received within `body_read_timeout_s` |
| 429 | `RATE_LIMITED` | per-source in-flight, concurrency, global or per-source bucket limit |
| 500 | `INTERNAL` | queue `CONFLICT`/`INTERNAL`, or any other failure |
| 503 | `UNAVAILABLE` | queue `UNAVAILABLE` |

The cause of a failure never appears in a body or a log. Every response, including errors and CORS preflight,
carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Limits (`GatewayLimits`)

| Field | Default | Meaning |
|---|---:|---|
| `max_request_bytes` | 65536 | largest accepted request body |
| `max_bundles` | 16 | bundles per `GET /bundles` |
| `max_page` | 32 | responses per page |
| `per_source_rate` / `per_source_burst` | 20.0 / 40 | token bucket per source key |
| `global_rate` / `global_burst` | 500.0 / 1000 | token bucket shared by all peers |
| `max_concurrency` | 64 | requests in flight; excess gets `429` with `Retry-After: 1` |
| `max_sources_tracked` | 10000 | per-source buckets kept (least recently used evicted) |
| `cors_origins` | `()` | CORS allow-list (see below) |
| `per_source_max_in_flight` | 8 | requests in flight per source key, 1..`max_concurrency`; excess gets `429` with `Retry-After: 1` |
| `body_read_timeout_s` | 10.0 | total deadline, 1.0..60.0 s, to receive a request body |
| `header_read_timeout_s` | 10.0 | total deadline, 1.0..60.0 s, to receive one request's header block; the connection is then closed without a response |
| `max_connections` | 512 | open connections per process in any state, at least `max_concurrency`; an excess connection is closed at once without a response |
| `max_header_bytes` | 8192 | 1024..12288; `raw_path` + query string + every header name and value, in bytes; excess gets `400` |
| `max_header_count` | 64 | 16..256; headers per request; excess gets `400` |
| `write_timeout_s` | 30.0 | 1.0..60.0 s for a client to drain response bytes the kernel could not take at once; the connection is then aborted |

Every request passes these checks in order, before routing and before any queue call:

0. Transfer-Encoding rule: any request carrying `Transfer-Encoding`, with or without `Content-Length`, gets
   `400 INVALID_ARGUMENT` with `Connection: close`, takes no slot and no token, and the connection is closed
   after the response;
1. per-source in-flight cap;
2. global concurrency;
3. global bucket;
4. per-source bucket;
5. header limits;
6. control-character path rule;
7. routing.

The in-flight slots taken in steps 1–2 are released in a `finally` (success, error, body deadline, client
disconnect, cancellation). The header limits are measured on the parsed request, so the answer does not depend on
how the bytes arrived; an oversized request spends rate budget, and a rate-limited one gets `429` unmeasured. A token is spent only when both buckets admit the request. `Retry-After` is the
whole number of seconds until one token is available, at least 1.

The **source key** is derived from the ASGI peer address: an IPv4 address keys on itself, an IPv4-mapped
IPv6 address on its IPv4 address, any other IPv6 address on its /64 network, and a missing or unparseable
peer on `"unknown"`. `X-Forwarded-For` and similar headers are never trusted.

**Deployment requirement.** Run the gateway under uvicorn with `uvicorn_config`, which sets
`proxy_headers=False`, `server_header=False` and `access_log=False` and never sets `forwarded_allow_ips`. With
uvicorn's defaults a loopback peer could spoof `X-Forwarded-For` and choose its own source key. Behind a reverse
proxy, every client shares the proxy's peer address, so the per-source limit collapses to the global limit. The
connection cap is global, not per source: one source can hold up to `max_connections` connections for
`header_read_timeout_s` each. That is accepted for this reference gateway; a production deployment puts
per-client connection limits in its fronting proxy. A fronting proxy must forward the client's `Content-Length`
framing and must not re-encode request bodies as chunked: the gateway refuses every request that carries
`Transfer-Encoding` (check step 0).

`create_app` and `uvicorn_config` raise `ValueError("INVALID_LIMITS")` unless every integer field is a
positive `int`, every rate is a finite positive `int` or `float` (`bool` is refused), `per_source_max_in_flight`
is at most `max_concurrency`, `body_read_timeout_s` and `header_read_timeout_s` are finite numbers in 1.0..60.0,
`max_connections` is an `int` of at least `max_concurrency`, `max_header_bytes` is an `int` in 1024..12288 and
`max_header_count` is an `int` in 16..256, and `write_timeout_s` is a finite number in 1.0..60.0. They then check
`cors_origins`.

**Response sizes.** Gateway JSON is compact and escape-free, so a page's size follows from the limits. At the
default limits a `GET /responses` page is at most 1,406,937 bytes (32 maximal frame envelopes of 32,926 bytes and
a 128-character `next` cursor) and a `GET /bundles` page at most 1,399,133 bytes (16 bundles of 65,536 bytes).
`FetchTransport`'s default `maxResponseBytes` (2,097,152) covers both. A host that raises `max_page` above 47 or
`max_bundles` above 23 passes a larger `maxResponseBytes`.

## Server hardening

`notes_gateway.server.uvicorn_config(app, *, limits=GatewayLimits(), host, port)` returns the `uvicorn.Config`
for the gateway. It runs uvicorn's h11 protocol with the gateway's hooks (never httptools), `ws="none"` (no
upgrade path, even if a WebSocket library is installed), `h11_max_incomplete_event_size=16384`,
`timeout_keep_alive=5` and `log_level="warning"`, and never sets `limit_concurrency`. ASGI middleware cannot do
the following, because uvicorn handles these paths before the app runs:

- **Header-read deadline.** The whole header block of each request must arrive within `header_read_timeout_s`,
  counted from the accepted connection or, on a kept-alive connection, from the previous response. Data does not
  reset it. On expiry the connection is closed and nothing is written.
- **Connection cap.** A connection beyond `max_connections` open connections is closed at once, and nothing is
  written. Other connections are unaffected.
- **Parse failures.** A request the HTTP parser rejects gets exactly `400 {"code":"INVALID_ARGUMENT"}` with
  `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and
  `Connection: close` (no CORS headers), and the connection is closed. If a response is already in progress on
  the connection, or the response is complete while the request body is still arriving, nothing is written; the
  connection is only closed. Every request gets at most one response.
- **Write deadline.** The write high-water mark is 0, so response bytes the kernel cannot take at once pause the
  writer. The client must then drain them within `write_timeout_s`, or the connection is aborted and the
  buffered bytes are discarded; the request ends as a client disconnect and its in-flight slots are released.
  Each pause starts a new deadline and a full drain cancels it. A client that pipelines requests and never reads
  therefore holds a slot for at most `write_timeout_s`.

The hooks rely on uvicorn 0.54.0 internals; any uvicorn version change re-runs their tests.

## CORS

- By default (`cors_origins=()`) no CORS header is ever sent: the web client must be served from the
  gateway's origin.
- Each `cors_origins` entry must be a browser-serialised origin: `https://host[:port]` with a lowercase DNS
  host, or a loopback `http://localhost`, `http://127.0.0.1` or `http://[::1]` origin, each with an optional
  non-default port. Anything else (`*`, `null`, a path, a trailing slash or space, non-loopback `http:`)
  raises `ValueError("INVALID_CORS_ORIGIN")` at `create_app`.
- Only a request with exactly one `Origin` header equal to an entry gets
  `Access-Control-Allow-Origin: <that origin>` and `Vary: Origin`, on every response kind.
- A preflight (`OPTIONS` with `Access-Control-Request-Method`) from an allowed origin gets `200` with
  `Access-Control-Allow-Methods: GET, POST` and `Access-Control-Allow-Headers: Content-Type`. Preflights
  spend rate budget like any other request.
- `Access-Control-Allow-Credentials` is never sent. The gateway uses no cookies or credentials.

## Logging

One `info` line per request on the `teecustody.gateway` logger, with outcome `GATEWAY_<CODE>` (`GATEWAY_OK`,
`GATEWAY_INVALID_ARGUMENT`, `GATEWAY_REQUEST_TIMEOUT`, `GATEWAY_RATE_LIMITED`, …) and no fields. The server
hooks log `GATEWAY_HEADER_TIMEOUT`, `GATEWAY_CONNECTION_LIMIT`, `GATEWAY_WRITE_TIMEOUT`, and
`GATEWAY_INVALID_ARGUMENT` for a parse failure, also without fields. Paths, ids, origins, peer addresses, request bytes and bodies are not logged.
uvicorn access logging must be disabled (`access_log=False`); uvicorn's own constant warning for a parse failure
remains and carries neither the input nor the peer.
