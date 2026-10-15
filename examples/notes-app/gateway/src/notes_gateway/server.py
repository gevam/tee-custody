"""The gateway's uvicorn configuration (INC-2-API §6 "Server hardening")."""

import fastapi
import uvicorn

from notes_gateway.limits import GatewayLimits as _GatewayLimits

__all__ = ["uvicorn_config"]


def uvicorn_config(
    app: fastapi.FastAPI, *, limits: _GatewayLimits = _GatewayLimits(), host: str, port: int
) -> uvicorn.Config:
    """The uvicorn configuration every runner of the gateway uses."""
    return uvicorn.Config(app, host=host, port=port)
