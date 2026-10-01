"""Simulator facade: issuer plus launcher socket, as a context manager."""

import ipaddress
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from types import TracebackType
from typing import Final

from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import SimConfigError, SimConfigErrorCode, SimulatorConfig
from teecustody_sim.constants import (
    DEFAULT_TOKEN_AUDIENCE,
    DEFAULT_TOKEN_MAX_AGE_S,
    MAX_SIGNERS,
    SIM_ISSUER,
)
from teecustody_sim.issuer import IssuerServer
from teecustody_sim.keys import SimKeys
from teecustody_sim.launcher import LauncherServer
from teecustody_sim.token import TokenMinter

_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
_LOOPBACK_V4: Final = ipaddress.IPv4Network("127.0.0.0/8")
_LOOPBACK_V6: Final = ipaddress.IPv6Address("::1")
_MAX_SOCKET_PATH_BYTES: Final = 100
_MAX_PORT: Final = 65535
_CREDENTIAL_VARIABLE: Final = "GOOGLE_APPLICATION_CREDENTIALS"
_CREDENTIAL_PREFIX: Final = "CLOUDSDK_AUTH_"
_DISCOVERY_PATH: Final = "/.well-known/openid-configuration"
_STATE_FILE_NAME: Final = "sim-state.json"
_STATE_VERSION: Final = 1
_STATE_FILE_MODE: Final = 0o600
_TOKEN_FILE_MODE: Final = 0o644


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


def _write_file(path: Path, text: str, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(descriptor, mode)
        handle.write(text)


def _state_document(config: SimulatorConfig, origin: str) -> dict[str, JsonValue]:
    launch = config.launch
    return {
        "state_version": _STATE_VERSION,
        "audience": config.audience,
        "issuer": SIM_ISSUER,
        "discovery_url": origin + _DISCOVERY_PATH,
        "jwks_origin": origin,
        "signers_required": config.signers_required,
        "token_ttl_s": config.token_ttl_s,
        "launch": {
            "image_reference": launch.image_reference,
            "image_digest": launch.image_digest,
            "args": list(launch.args),
            "env": dict(launch.env),
        },
    }


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
        self._keys: SimKeys | None = None
        self._issuer: IssuerServer | None = None
        self._launcher: LauncherServer | None = None

    def __enter__(self) -> "Simulator":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        config = self._config
        _validate(config, os.environ if self._environ is None else self._environ)
        try:
            self._serve(config)
        except BaseException:
            self.stop()
            raise

    def _serve(self, config: SimulatorConfig) -> None:
        keys = SimKeys.load_or_create(config.state_dir, config.signers_required)
        self._keys = keys
        self._issuer = IssuerServer(
            config.issuer_host,
            config.issuer_port,
            issuer=SIM_ISSUER,
            jwks=keys.issuer_jwks(),
            limits=config.limits,
        )
        self._issuer.start()
        minter = TokenMinter(
            keys,
            config.launch,
            ttl_s=config.token_ttl_s,
            token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S,
        )
        self._launcher = LauncherServer(
            config.socket_path,
            mint=lambda audience, nonces: minter.mint(audience, nonces, int(self._clock())),
            limits=config.limits,
        )
        self._launcher.start()
        default_token = minter.mint(DEFAULT_TOKEN_AUDIENCE, [], int(self._clock()))
        _write_file(config.token_file_path, default_token, _TOKEN_FILE_MODE)
        state = _state_document(config, self._issuer.origin)
        _write_file(config.state_dir / _STATE_FILE_NAME, json.dumps(state), _STATE_FILE_MODE)

    def stop(self) -> None:
        if self._launcher is not None:
            self._launcher.stop()
        if self._issuer is not None:
            self._issuer.stop()

    @property
    def issuer_origin(self) -> str:
        if self._issuer is None:
            raise SimConfigError(SimConfigErrorCode.STATE_NOT_INITIALISED)
        return self._issuer.origin

    @property
    def discovery_url(self) -> str:
        return self.issuer_origin + _DISCOVERY_PATH

    @property
    def keys(self) -> SimKeys:
        if self._keys is None:
            raise SimConfigError(SimConfigErrorCode.STATE_NOT_INITIALISED)
        return self._keys
