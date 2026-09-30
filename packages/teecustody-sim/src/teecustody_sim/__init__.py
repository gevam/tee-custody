"""Development-only Confidential Space simulator for teecustody (spec §15)."""

from teecustody_sim.alterations import (
    Alteration,
    AlterClaim,
    ClaimPath,
    DropClaim,
    JsonValue,
    NamedCase,
)
from teecustody_sim.cases import NEGATIVE_CASES, NegativeCase
from teecustody_sim.cli import main
from teecustody_sim.config import (
    LaunchConfig,
    SimConfigError,
    SimConfigErrorCode,
    SimLimits,
    SimulatorConfig,
)
from teecustody_sim.constants import (
    CONTAINER_LAUNCHER_DIR,
    DBGSTAT_DISABLED,
    DEFAULT_ISSUER_HOST,
    DEFAULT_ISSUER_PORT,
    DEFAULT_SIGNERS_REQUIRED,
    DEFAULT_STATE_DIR,
    DEFAULT_TOKEN_AUDIENCE,
    DEFAULT_TOKEN_FILE_NAME,
    DEFAULT_TOKEN_MAX_AGE_S,
    DEV_SIGNER_ALGORITHM,
    JWS_ALG,
    LAUNCHER_SOCKET_NAME,
    MAX_SIGNERS,
    SIM_HWMODEL,
    SIM_ISSUER,
    SIM_TOKEN_TTL_S,
    SUPPORT_ATTRIBUTES,
    SWNAME,
)
from teecustody_sim.issuer import IssuerServer
from teecustody_sim.keys import SignerKeyMaterial, SimKeys
from teecustody_sim.launcher import LauncherServer
from teecustody_sim.profile import build_trust_profile, launch_config_hashes
from teecustody_sim.runtime import ContainerRuntime
from teecustody_sim.simulator import Simulator
from teecustody_sim.token import TokenMinter, frame_jws, image_signature_payload, parse_alteration
from teecustody_sim.vectors import generate_corpus, generate_suite

__all__ = [
    "CONTAINER_LAUNCHER_DIR",
    "DBGSTAT_DISABLED",
    "DEFAULT_ISSUER_HOST",
    "DEFAULT_ISSUER_PORT",
    "DEFAULT_SIGNERS_REQUIRED",
    "DEFAULT_STATE_DIR",
    "DEFAULT_TOKEN_AUDIENCE",
    "DEFAULT_TOKEN_FILE_NAME",
    "DEFAULT_TOKEN_MAX_AGE_S",
    "DEV_SIGNER_ALGORITHM",
    "JWS_ALG",
    "LAUNCHER_SOCKET_NAME",
    "MAX_SIGNERS",
    "NEGATIVE_CASES",
    "SIM_HWMODEL",
    "SIM_ISSUER",
    "SIM_TOKEN_TTL_S",
    "SUPPORT_ATTRIBUTES",
    "SWNAME",
    "AlterClaim",
    "Alteration",
    "ClaimPath",
    "ContainerRuntime",
    "DropClaim",
    "IssuerServer",
    "JsonValue",
    "LaunchConfig",
    "LauncherServer",
    "NamedCase",
    "NegativeCase",
    "SignerKeyMaterial",
    "SimConfigError",
    "SimConfigErrorCode",
    "SimKeys",
    "SimLimits",
    "Simulator",
    "SimulatorConfig",
    "TokenMinter",
    "build_trust_profile",
    "frame_jws",
    "generate_corpus",
    "generate_suite",
    "image_signature_payload",
    "launch_config_hashes",
    "main",
    "parse_alteration",
]
