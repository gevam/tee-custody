"""Simulator constants (spec §14, §15; FACTS)."""

from typing import Final

SIM_ISSUER: Final = "https://tee-sim.localhost"
SIM_HWMODEL: Final = "SIMULATED"
SIM_TOKEN_TTL_S: Final = 3600
DEFAULT_TOKEN_MAX_AGE_S: Final = 3600
DEFAULT_SIGNERS_REQUIRED: Final = 2
MAX_SIGNERS: Final = 16
DEFAULT_ISSUER_HOST: Final = "127.0.0.1"
DEFAULT_ISSUER_PORT: Final = 8791
DEFAULT_STATE_DIR: Final = ".teecustody-sim"
CONTAINER_LAUNCHER_DIR: Final = "/run/container_launcher"
LAUNCHER_SOCKET_NAME: Final = "teeserver.sock"
DEFAULT_TOKEN_FILE_NAME: Final = "attestation_verifier_claims_token"  # noqa: S105 - a file name
DEFAULT_TOKEN_AUDIENCE: Final = "https://sts.googleapis.com"  # noqa: S105 - an audience URL
SWNAME: Final = "CONFIDENTIAL_SPACE"
DBGSTAT_DISABLED: Final = "disabled-since-boot"
SUPPORT_ATTRIBUTES: Final = ("LATEST", "STABLE", "USABLE")
DEV_SIGNER_ALGORITHM: Final = "RSASSA_PSS_SHA256"
JWS_ALG: Final = "RS256"
