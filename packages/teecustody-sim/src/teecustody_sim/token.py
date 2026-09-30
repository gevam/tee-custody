"""Simulator token minting and alterations."""

from collections.abc import Callable, Sequence
from typing import Literal

from teecustody_sim.alterations import Alteration, JsonValue
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import SIM_ISSUER
from teecustody_sim.keys import SimKeys


def image_signature_payload(image_reference: str, image_digest: str) -> bytes:
    raise NotImplementedError


def frame_jws(header: bytes, payload: bytes, sign: Callable[[bytes], bytes]) -> str:
    raise NotImplementedError


def parse_alteration(kind: Literal["alter", "drop", "case"], text: str) -> Alteration:
    raise NotImplementedError


class TokenMinter:
    def __init__(
        self,
        keys: SimKeys,
        launch: LaunchConfig,
        *,
        issuer: str = SIM_ISSUER,
        ttl_s: int,
        token_max_age_s: int,
    ) -> None:
        raise NotImplementedError

    def claims(self, audience: str, nonces: Sequence[str], now: int) -> dict[str, JsonValue]:
        raise NotImplementedError

    def mint(
        self,
        audience: str,
        nonces: Sequence[str],
        now: int,
        alteration: Alteration | None = None,
    ) -> str:
        raise NotImplementedError
