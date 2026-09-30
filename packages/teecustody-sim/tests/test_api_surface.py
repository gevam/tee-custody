"""T-01: the frozen `teecustody_sim` public API (API.md §C) exists as transcribed."""

from __future__ import annotations

import pytest

import teecustody_sim

PUBLIC_NAMES: tuple[str, ...] = (
    # constants.py
    "SIM_ISSUER",
    "SIM_HWMODEL",
    "SIM_TOKEN_TTL_S",
    "DEFAULT_TOKEN_MAX_AGE_S",
    "DEFAULT_SIGNERS_REQUIRED",
    "MAX_SIGNERS",
    "DEFAULT_ISSUER_HOST",
    "DEFAULT_ISSUER_PORT",
    "DEFAULT_STATE_DIR",
    "CONTAINER_LAUNCHER_DIR",
    "LAUNCHER_SOCKET_NAME",
    "DEFAULT_TOKEN_FILE_NAME",
    "DEFAULT_TOKEN_AUDIENCE",
    "SWNAME",
    "DBGSTAT_DISABLED",
    "SUPPORT_ATTRIBUTES",
    "DEV_SIGNER_ALGORITHM",
    "JWS_ALG",
    # config.py
    "LaunchConfig",
    "SimLimits",
    "SimulatorConfig",
    "SimConfigErrorCode",
    "SimConfigError",
    # alterations.py
    "JsonValue",
    "ClaimPath",
    "AlterClaim",
    "DropClaim",
    "NamedCase",
    "Alteration",
    # cases.py
    "NegativeCase",
    "NEGATIVE_CASES",
    # keys.py
    "SignerKeyMaterial",
    "SimKeys",
    # token.py
    "image_signature_payload",
    "frame_jws",
    "parse_alteration",
    "TokenMinter",
    # issuer.py, launcher.py, simulator.py
    "IssuerServer",
    "LauncherServer",
    "Simulator",
    # runtime.py, cli.py
    "ContainerRuntime",
    "main",
    # profile.py, vectors.py
    "launch_config_hashes",
    "build_trust_profile",
    "generate_suite",
    "generate_corpus",
)


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_public_name_is_importable_from_package_root(name: str) -> None:
    assert hasattr(teecustody_sim, name), name


def test_cli_entry_point_is_cli_main() -> None:
    from teecustody_sim import cli

    assert teecustody_sim.main is cli.main
