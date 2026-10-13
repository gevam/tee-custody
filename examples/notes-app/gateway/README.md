# notes-gateway — reference queue gateway

An **untrusted** HTTP relay between browsers and the workload's queue (INC-2-API §6; FR-5, SR-1, SR-3,
SR-4; D-003). It is an example, not a product. A host can replace it with any gateway that implements the same
HTTP contract.

The gateway relays opaque bytes. It holds no keys, authenticates nobody, and never decodes, logs or echoes a
request or response body. A route id is a routing hint, not an identity. Only the channel inside the TEE
authenticates a client.

```python
from notes_gateway import GatewayLimits, create_app

app = create_app(queue)  # queue: any teecustody.queue.RelayQueue
```

## Routes

| Route | Request | Success | Errors |
|---|---|---|---|
| `GET /bundles` | no body | `200 {"bundles":[{"instance_id":"<32hex>","bundle":"<b64url>"}]}` (at most `max_bundles`) | 503, 500 |
| `POST /requests/{instance}` | `Content-Type: application/octet-stream`, `Content-Length` required, 1..`max_request_bytes` raw envelope bytes | `202 {"request_id":"<32hex>"}` (relay id minted by the gateway) | 400, 404 `UNKNOWN_INSTANCE`, 503, 500 |
| `GET /responses/{client}?after=<cursor>` | `after` optional | `200 {"responses":[{"request_id":"<32hex>","body":"<b64url>"}],"next":"<cursor>"\|null}` (at most `max_page`) | 400, 503, 500 |
| any request over a limit | — | — | `429 {"code":"RATE_LIMITED"}` with `Retry-After: <int s>` |
| other path / method | — | — | `404 {"code":"NOT_FOUND"}` / `405 {"code":"METHOD_NOT_ALLOWED"}` |

- `b64url` is RFC 4648 §5 base64url without padding. `next: null` means "omit `after` next time".
- `{instance}` and `{client}` must be exactly 32 lowercase hex characters. `after` must match
  `[A-Za-z0-9_-]{1,128}` and appear at most once. Both are checked by full match on the decoded value, so a
  trailing `%0A`, uppercase hex, or 31 or 33 characters is a `400`. No queue call is made.
- The body is read as a stream and refused with `400` as soon as it exceeds `Content-Length`. A missing,
  repeated or non-decimal `Content-Length`, a length outside 1..`max_request_bytes`, a body shorter than
  declared, or a `Content-Type` other than exactly `application/octet-stream` (parameters included) is a `400`.
- An unknown client route returns `200` with an empty page, never an error, so route probing reveals nothing.
- JSON is compact (`separators=(",", ":")`) with `Content-Type: application/json`. There are no OpenAPI or
  docs routes, and no trailing-slash redirects.

## Error bodies

Every error body is exactly `{"code":"<CODE>"}`:

| Status | Code | When |
|---|---|---|
| 400 | `INVALID_ARGUMENT` | bad route id, cursor, headers or body; queue `INVALID_ARGUMENT` |
| 404 | `UNKNOWN_INSTANCE` | queue `NOT_FOUND` (no live bundle for the instance) |
| 404 | `NOT_FOUND` | unknown path |
| 405 | `METHOD_NOT_ALLOWED` | unknown method on a known path |
| 429 | `RATE_LIMITED` | concurrency, global or per-source limit |
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
| `per_source_rate` / `per_source_burst` | 20.0 / 40 | token bucket per peer address |
| `global_rate` / `global_burst` | 500.0 / 1000 | token bucket shared by all peers |
| `max_concurrency` | 64 | requests in flight; excess gets `429` with `Retry-After: 1` |
| `max_sources_tracked` | 10000 | per-source buckets kept (least recently used evicted) |
| `cors_origins` | `()` | CORS allow-list (see below) |

Limits are applied to every request before any route runs: concurrency, then the global bucket, then the
per-source bucket. A token is spent only when both buckets admit the request. `Retry-After` is the whole
number of seconds until one token is available, at least 1. The source is the ASGI peer address
(`"unknown"` when absent). `X-Forwarded-For` and similar headers are never trusted. Behind a reverse proxy, every client shares the proxy's peer address, so the per-source limit collapses to the global limit.

`create_app` raises `ValueError("INVALID_LIMITS")` unless every integer field is a positive `int` and every
rate is a finite positive `int` or `float` (`bool` is refused). It then checks `cors_origins`.

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
`GATEWAY_INVALID_ARGUMENT`, `GATEWAY_RATE_LIMITED`, …) and no fields. Paths, ids, origins and bodies are not
logged. Run it under uvicorn with access logging disabled.
