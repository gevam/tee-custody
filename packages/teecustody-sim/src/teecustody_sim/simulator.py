"""Simulator facade: issuer plus launcher socket, as a context manager."""

import ipaddress
import os
import re
import time
from collections.abc import Callable, Mapping
from types import TracebackType
from typing import Final

from teecustody_sim.config import SimConfigError, SimConfigErrorCode, SimulatorConfig
from teecustody_sim.constants import MAX_SIGNERS
from teecustody_sim.keys import SimKeys
from teecustody_sim.token import TokenMinter

_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_LOOPBACK_V4: Final = ipaddress.IPv4Network("127.0.0.0/8")
_LOOPBACK_V6: Final = ipaddress.IPv6Address("::1")
_MAX_SOCKET_PATH_BYTES: Final = 100
_MAX_PORT: Final = 65535
_CREDENTIAL_VARIABLE: Final = "GOOGLE_APPLICATION_CREDENTIALS"
_CREDENTIAL_PREFIX: Final = "CLOUDSDK_AUTH_"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address in _LOOPBACK_V4
    return address == _LOOPBACK_V6


def _validate(config: SimulatorConfig, environ: Mapping[str, str]) -> None:
    """Every spec §15.5 / API.md §C startup rule, checked before any file or socket exists."""
    if not 1 <= config.signers_required <= MAX_SIGNERS:
        raise SimConfigError(SimConfigErrorCode.INVALID_SIGNERS_REQUIRED)
    if not config.allow_non_loopback and not _is_loopback(config.issuer_host):
        raise SimConfigError(SimConfigErrorCode.NON_LOOPBACK_NOT_ALLOWED)
    launch = config.launch
    env_names = [name for name, _ in launch.env]
    if (
        not launch.image_reference
        or not _DIGEST.fullmatch(launch.image_digest)
        or len(set(env_names)) != len(env_names)
        or not config.audience
    ):
        raise SimConfigError(SimConfigErrorCode.INVALID_LAUNCH_CONFIG)
    if (
        len(os.fsencode(config.socket_path)) > _MAX_SOCKET_PATH_BYTES
        or not config.socket_path.parent.is_dir()
        or not config.token_file_path.parent.is_dir()
    ):
        raise SimConfigError(SimConfigErrorCode.INVALID_PATH)
    if not 0 <= config.issuer_port <= _MAX_PORT:
        raise SimConfigError(SimConfigErrorCode.INVALID_PORT)
    if _CREDENTIAL_VARIABLE in environ or any(
        name.startswith(_CREDENTIAL_PREFIX) for name in environ
    ):
        raise SimConfigError(SimConfigErrorCode.PRODUCTION_CREDENTIALS_PRESENT)


class Simulator:
    def __init__(
        self,
        config: SimulatorConfig,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config
        self._environ = environ
        self._clock = clock

    def __enter__(self) -> "Simulator":
        raise NotImplementedError("T-08")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        raise NotImplementedError("T-08")

    def start(self) -> None:
        _validate(self._config, os.environ if self._environ is None else self._environ)

    def stop(self) -> None:
        raise NotImplementedError("T-08")

    @property
    def issuer_origin(self) -> str:
        raise NotImplementedError("T-08")

    @property
    def discovery_url(self) -> str:
        raise NotImplementedError("T-08")

    @property
    def keys(self) -> SimKeys:
        raise NotImplementedError("T-08")
