"""Simulator configuration: plain frozen dataclasses; validation lives with the simulator."""

from dataclasses import dataclass
from enum import StrEnum, auto
from pathlib import Path


@dataclass(frozen=True)
class LaunchConfig:
    image_reference: str
    image_digest: str
    args: tuple[str, ...]
    env: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class SimLimits:
    max_request_bytes: int
    max_concurrent_requests: int


@dataclass(frozen=True)
class SimulatorConfig:
    state_dir: Path
    socket_path: Path
    token_file_path: Path
    launch: LaunchConfig
    audience: str
    issuer_host: str
    issuer_port: int
    signers_required: int
    token_ttl_s: int
    allow_non_loopback: bool
    limits: SimLimits


class SimConfigErrorCode(StrEnum):
    INVALID_SIGNERS_REQUIRED = auto()
    NON_LOOPBACK_NOT_ALLOWED = auto()
    INVALID_LAUNCH_CONFIG = auto()
    PRODUCTION_CREDENTIALS_PRESENT = auto()
    INVALID_PATH = auto()
    INVALID_PORT = auto()
    STATE_NOT_INITIALISED = auto()


class SimConfigError(Exception):
    code: SimConfigErrorCode
