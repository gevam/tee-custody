"""The gateway's uvicorn configuration (INC-2-API §6 "Server hardening")."""

import asyncio

import fastapi
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol as _H11Protocol

from notes_gateway.app import validate_limits as _validate_limits
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
    """uvicorn's h11 protocol with the §6 header and write deadlines and the connection cap."""
    header_read_timeout_s = limits.header_read_timeout_s
    max_connections = limits.max_connections
    write_timeout_s = limits.write_timeout_s

    class _GatewayProtocol(_H11Protocol):
        _deadline: asyncio.TimerHandle | None = None
        _write_deadline: asyncio.TimerHandle | None = None
        _idle_state: object = None

        def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
            # h11's server state before any request (IDLE), kept for identity checks: no h11 import.
            self._idle_state = self.conn.our_state
            super().connection_made(transport)
            if len(self.connections) > max_connections:
                self.transport.close()
                _LOG.info("GATEWAY_CONNECTION_LIMIT")
                return
            # Any response bytes the kernel cannot take at once pause the writer (D-05).
            transport.set_write_buffer_limits(high=0)
            self._arm()

        def connection_lost(self, exc: Exception | None) -> None:
            for handle in (self._deadline, self._write_deadline):
                if handle is not None:
                    handle.cancel()
            super().connection_lost(exc)

        def pause_writing(self) -> None:
            super().pause_writing()
            if self._write_deadline is None:
                self._write_deadline = self.loop.call_later(write_timeout_s, self._write_expired)

        def resume_writing(self) -> None:
            if self._write_deadline is not None:
                self._write_deadline.cancel()
                self._write_deadline = None
            super().resume_writing()

        def _write_expired(self) -> None:
            """The peer did not drain buffered output in time: abort (discarding it, as close()
            would wait for a peer that never reads). uvicorn's connection_lost then ends the
            request as a client disconnect, so the gateway releases its in-flight slots."""
            self._write_deadline = None
            if self.flow.write_paused:
                self.transport.abort()
                _LOG.info("GATEWAY_WRITE_TIMEOUT")

        def on_response_complete(self) -> None:
            # Arm first: super() may parse a pipelined request, which must start a new cycle.
            if not self.transport.is_closing():
                self._arm()
            super().on_response_complete()

        def send_400_response(self, msg: str) -> None:
            """The §6 parse-failure answer in place of uvicorn's text/plain body. It is written only
            when no response has begun for the request being parsed: no cycle, the current response
            not started, or h11's server state back at IDLE (the previous exchange ended and a new
            request is being parsed; a parse failure leaves our_state unchanged). Otherwise (a
            response in progress, or one sent while the same request's body still arrives) nothing
            is written and the connection is only closed."""
            cycle = self.cycle
            if (
                cycle is None
                or not cycle.response_started
                or self.conn.our_state is self._idle_state
            ):
                self.transport.write(_PARSE_FAILURE_400)
            self.transport.close()
            _LOG.info("GATEWAY_INVALID_ARGUMENT")

        def _arm(self) -> None:
            if self._deadline is not None:
                self._deadline.cancel()
            self._deadline = self.loop.call_later(header_read_timeout_s, self._expire, self.cycle)

        def _expire(self, cycle: object | None) -> None:
            """Close if no request has been parsed since arming (a new request is a new cycle)."""
            if self.cycle is cycle and not self.transport.is_closing():
                self.transport.close()
                _LOG.info("GATEWAY_HEADER_TIMEOUT")

    return _GatewayProtocol


def uvicorn_config(
    app: fastapi.FastAPI, *, limits: _GatewayLimits = _GatewayLimits(), host: str, port: int
) -> uvicorn.Config:
    """The uvicorn configuration every runner of the gateway uses. Pass the `limits` given to
    `create_app`; invalid limits raise `ValueError("INVALID_LIMITS")` as `create_app` does."""
    _validate_limits(limits)
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
