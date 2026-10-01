"""Loopback OIDC issuer: discovery document and JWKS."""

from collections.abc import Mapping

from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import SimLimits


class IssuerServer:
    def __init__(
        self,
        host: str,
        port: int,
        *,
        issuer: str,
        jwks: Mapping[str, JsonValue],
        limits: SimLimits,
    ) -> None:
        raise NotImplementedError("T-08")

    def start(self) -> None:
        raise NotImplementedError("T-08")

    def stop(self) -> None:
        raise NotImplementedError("T-08")

    @property
    def origin(self) -> str:
        raise NotImplementedError("T-08")
