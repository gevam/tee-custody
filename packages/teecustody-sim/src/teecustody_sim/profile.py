"""Development trust profile (API.md §E)."""

import hashlib
from collections.abc import Sequence

from teecustody.wire import CanonicalValue, encode
from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import DEFAULT_TOKEN_MAX_AGE_S
from teecustody_sim.keys import SignerKeyMaterial


def launch_config_hashes(args: Sequence[str], env: Sequence[tuple[str, str]]) -> tuple[str, str]:
    args_value: list[CanonicalValue] = list(args)
    env_value: dict[str, CanonicalValue] = dict(env)
    return (
        hashlib.sha256(encode(args_value)).hexdigest(),
        hashlib.sha256(encode(env_value)).hexdigest(),
    )


def build_trust_profile(
    *,
    discovery_url: str,
    jwks_origin: str,
    expected_audience: str,
    launch: LaunchConfig,
    signers: Sequence[SignerKeyMaterial],
    signers_required: int,
    token_max_age_s: int = DEFAULT_TOKEN_MAX_AGE_S,
) -> dict[str, JsonValue]:
    raise NotImplementedError("T-17")
