"""Simulator configuration: plain frozen dataclasses; validation lives with the simulator."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from teecustody_sim.constants import (
    DEFAULT_ISSUER_HOST,
    DEFAULT_ISSUER_PORT,
    DEFAULT_SIGNERS_REQUIRED,
    SIM_TOKEN_TTL_S,
)


@dataclass(frozen=True)
class LaunchConfig:
    image_reference: str
    image_digest: str  # "sha256:<64 lowercase hex>"
    args: tuple[str, ...]
    env: tuple[tuple[str, str], ...]  # (name, value) pairs


@dataclass(frozen=True)
class SimLimits:
    max_request_bytes: int = 4096
    max_concurrent_requests: int = 8


@dataclass(frozen=True)
class SimulatorConfig:
    state_dir: Path
    socket_path: Path
    token_file_path: Path
    launch: LaunchConfig
    audience: str  # recorded in sim-state.json for `profile`
    issuer_host: str = DEFAULT_ISSUER_HOST
    issuer_port: int = DEFAULT_ISSUER_PORT  # 0 = ephemeral
    signers_required: int = DEFAULT_SIGNERS_REQUIRED
    token_ttl_s: int = SIM_TOKEN_TTL_S
    allow_non_loopback: bool = False
    limits: SimLimits = SimLimits()


class SimConfigErrorCode(StrEnum):
    INVALID_SIGNERS_REQUIRED = "INVALID_SIGNERS_REQUIRED"
    NON_LOOPBACK_NOT_ALLOWED = "NON_LOOPBACK_NOT_ALLOWED"
    INVALID_LAUNCH_CONFIG = "INVALID_LAUNCH_CONFIG"
    PRODUCTION_CREDENTIALS_PRESENT = "PRODUCTION_CREDENTIALS_PRESENT"
    INVALID_PATH = "INVALID_PATH"
    INVALID_PORT = "INVALID_PORT"
    STATE_NOT_INITIALISED = "STATE_NOT_INITIALISED"
    BIND_FAILED = "BIND_FAILED"


class SimConfigError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: SimConfigErrorCode

    def __init__(self, code: SimConfigErrorCode) -> None:
        super().__init__(code.value)
        self.code = code
