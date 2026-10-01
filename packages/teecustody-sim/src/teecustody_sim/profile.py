"""Development trust profile (API.md §E)."""

import hashlib
from collections.abc import Sequence

from teecustody.wire import CanonicalValue, encode
from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import DEFAULT_TOKEN_MAX_AGE_S, SIM_HWMODEL, SIM_ISSUER
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
    signer_keys: list[JsonValue] = [
        {"key_id": hashlib.sha256(signer.spki_der).hexdigest(), "algorithm": signer.algorithm}
        for signer in signers
    ]
    if signers_required > len(signers):
        raise ValueError("INVALID_SIGNERS_REQUIRED")
    args_hash, env_hash = launch_config_hashes(launch.args, launch.env)
    return {
        "profile_version": 1,
        "profile_kind": "development",
        "token_type": "OIDC",
        "issuer": SIM_ISSUER,
        "discovery_url": discovery_url,
        "jwks_origin": jwks_origin,
        "expected_audience": expected_audience,
        "token_max_age_s": token_max_age_s,
        "allowed_hwmodels": [SIM_HWMODEL],
        "allowed_digests": [launch.image_digest],
        "signer_keys": signer_keys,
        "signers_required": signers_required,
        "expected_args_hash": args_hash,
        "expected_env_hash": env_hash,
    }
