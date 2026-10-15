"""The gateway's uvicorn configuration (INC-2-API §6 "Server hardening")."""

import fastapi
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol as _H11Protocol

from notes_gateway.app import _validate
from notes_gateway.limits import GatewayLimits as _GatewayLimits

__all__ = ["uvicorn_config"]


def _protocol_class(limits: _GatewayLimits) -> type[_H11Protocol]:
    class _GatewayProtocol(_H11Protocol):
        pass

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
