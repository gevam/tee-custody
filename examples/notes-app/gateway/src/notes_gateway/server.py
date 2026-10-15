"""The gateway's uvicorn configuration (INC-2-API §6 "Server hardening")."""

import asyncio

import fastapi
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol as _H11Protocol
from uvicorn.protocols.http.h11_impl import RequestResponseCycle as _RequestResponseCycle

from notes_gateway.app import _validate
from notes_gateway.limits import GatewayLimits as _GatewayLimits
from teecustody.obs import get_logger as _get_logger

__all__ = ["uvicorn_config"]

_LOG = _get_logger("gateway")
# §6 "Parse failures": the exact bytes for a request the HTTP parser rejects. No CORS headers.
_PARSE_FAILURE_400 = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"content-type: application/json\r\n"
    b"content-length: 27\r\n"
    b"cache-control: no-store\r\n"
    b"x-content-type-options: nosniff\r\n"
    b"connection: close\r\n"
    b"\r\n"
    b'{"code":"INVALID_ARGUMENT"}'
)


def _protocol_class(limits: _GatewayLimits) -> type[_H11Protocol]:
    """uvicorn's h11 protocol with the §6 header-read deadline and connection cap."""
    header_read_timeout_s = limits.header_read_timeout_s
    max_connections = limits.max_connections

    class _GatewayProtocol(_H11Protocol):
        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            super().connection_made(transport)
            if len(self.connections) > max_connections:
                self.transport.close()
                _LOG.info("GATEWAY_CONNECTION_LIMIT")
                return
            self._arm()

        def on_response_complete(self) -> None:
            # Arm first: super() may parse a pipelined request, which must start a new cycle.
            self._arm()
            super().on_response_complete()

        def send_400_response(self, msg: str) -> None:
            """The §6 parse-failure answer in place of uvicorn's text/plain body."""
            self.transport.write(_PARSE_FAILURE_400)
            self.transport.close()
            _LOG.info("GATEWAY_INVALID_ARGUMENT")

        def _arm(self) -> None:
            self.loop.call_later(header_read_timeout_s, self._expire, self.cycle)

        def _expire(self, cycle: _RequestResponseCycle | None) -> None:
            """Close if no request has been parsed since arming (a new request is a new cycle)."""
            if self.cycle is cycle:
                self.transport.close()
                _LOG.info("GATEWAY_HEADER_TIMEOUT")

    return _GatewayProtocol


def uvicorn_config(
    app: fastapi.FastAPI, *, limits: _GatewayLimits = _GatewayLimits(), host: str, port: int
) -> uvicorn.Config:
    """The uvicorn configuration every runner of the gateway uses. Pass the `limits` given to
    `create_app`; invalid limits raise `ValueError("INVALID_LIMITS")` as `create_app` does."""
    _validate(limits)
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        http=_protocol_class(limits),
        ws="none",
        proxy_headers=False,
        server_header=False,
        access_log=False,
        h11_max_incomplete_event_size=16384,
        timeout_keep_alive=5,
        log_level="warning",
    )
