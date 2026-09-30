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
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    @property
    def origin(self) -> str:
        raise NotImplementedError
