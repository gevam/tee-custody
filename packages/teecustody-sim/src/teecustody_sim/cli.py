"""`teecustody-sim` command line."""

import argparse
import json
import logging
import os
import re
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final, NoReturn

from teecustody.obs import configure_logging
from teecustody_sim.config import (
    LaunchConfig,
    SimConfigError,
    SimConfigErrorCode,
    SimulatorConfig,
)
from teecustody_sim.constants import (
    DEFAULT_ISSUER_HOST,
    DEFAULT_ISSUER_PORT,
    DEFAULT_SIGNERS_REQUIRED,
    DEFAULT_STATE_DIR,
    DEFAULT_TOKEN_FILE_NAME,
    DEFAULT_TOKEN_MAX_AGE_S,
    LAUNCHER_SOCKET_NAME,
)
from teecustody_sim.keys import SimKeys
from teecustody_sim.profile import build_trust_profile
from teecustody_sim.runtime import ContainerRuntime
from teecustody_sim.simulator import Simulator
from teecustody_sim.token import TokenMinter, parse_alteration
from teecustody_sim.vectors import generate_corpus, generate_suite

_STATE_FILE_NAME: Final = "sim-state.json"
_USAGE_ERROR: Final = "INVALID_ARGUMENT"
_PROFILE_FILE_MODE: Final = 0o644
_CORPUS_SEED: Final = 1
_CORPUS_COUNT: Final = 512
_SUITE_PATH: Final = Path("attestation", "suite.cbor")  # API.md §C `vectors`
_CORPUS_PATH: Final = Path("wire", "differential-corpus.json")
_STATE_DIR_MODE: Final = 0o700
_LAUNCHER_DIR_MODE: Final = 0o755
_LAUNCHER_DIR_NAME: Final = "launcher"
_DECIMAL: Final = re.compile(r"[0-9]{1,5}", re.ASCII)
_ERROR_CODE: Final = re.compile(r"[A-Z][A-Z0-9_]*", re.ASCII)
_INTERNAL: Final = "INTERNAL"
_STOP_SIGNALS: Final = (signal.SIGINT, signal.SIGTERM)


class _UsageError(Exception):
    """Raised instead of argparse's own exit, so `main` returns and prints only a code."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise _UsageError(_USAGE_ERROR)


def _text(value: str) -> str:
    """Command-line text must be valid UTF-8; undecodable argv bytes arrive as lone surrogates."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise argparse.ArgumentTypeError(_USAGE_ERROR) from None
    return value


def _env(value: str) -> tuple[str, str]:
    name, separator, env_value = _text(value).partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(_USAGE_ERROR)
    return name, env_value


def _decimal(value: str) -> int:
    """ASCII digits only: `int()` alone would also accept signs, spaces and non-ASCII digits."""
    if _DECIMAL.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(_USAGE_ERROR)
    return int(value)


def _launch(document: dict[str, Any]) -> LaunchConfig:
    launch = document["launch"]
    return LaunchConfig(
        image_reference=launch["image_reference"],
        image_digest=launch["image_digest"],
        args=tuple(launch["args"]),
        env=tuple(launch["env"].items()),
    )


def _read_state(state_dir: Path) -> dict[str, Any]:
    try:
        text = (state_dir / _STATE_FILE_NAME).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SimConfigError(SimConfigErrorCode.STATE_NOT_INITIALISED) from None
    document: dict[str, Any] = json.loads(text)
    return document


def _token(options: argparse.Namespace) -> int:
    state_dir: Path = options.state_dir
    document = _read_state(state_dir)
    keys = SimKeys.load_or_create(state_dir, document["signers_required"])
    minter = TokenMinter(
        keys,
        _launch(document),
        ttl_s=document["token_ttl_s"],
        token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S,
    )
    alteration = None
    for kind in ("alter", "drop", "case"):
        if getattr(options, kind) is not None:
            alteration = parse_alteration(kind, getattr(options, kind))
    token = minter.mint(options.audience, options.nonce, int(time.time()), alteration)
    sys.stdout.write(token + "\n")
    return 0


def _write_public_file(path: Path, text: str) -> None:
    """Create or replace `path` with mode 0644, never following a symlink at `path`."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, _PROFILE_FILE_MODE)
    except OSError:  # ELOOP for a symlink; also a missing parent or a directory at `path`
        raise SimConfigError(SimConfigErrorCode.INVALID_PATH) from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(descriptor, _PROFILE_FILE_MODE)
        handle.write(text)


def _profile(options: argparse.Namespace) -> int:
    state_dir: Path = options.state_dir
    document = _read_state(state_dir)
    keys = SimKeys.load_or_create(state_dir, document["signers_required"])
    profile = build_trust_profile(
        discovery_url=document["discovery_url"],
        jwks_origin=document["jwks_origin"],
        expected_audience=document["audience"],
        launch=_launch(document),
        signers=keys.signers,
        signers_required=document["signers_required"],
    )
    _write_public_file(options.out, json.dumps(profile, indent=2, sort_keys=True) + "\n")
    return 0


def _launcher_dir(state_dir: Path) -> Path:
    """`STATE/launcher`, a real directory (never a symlink) with mode 0755 for the container."""
    state_dir.mkdir(mode=_STATE_DIR_MODE, parents=True, exist_ok=True)
    launcher_dir = state_dir / _LAUNCHER_DIR_NAME
    try:
        launcher_dir.mkdir(mode=_LAUNCHER_DIR_MODE)
    except FileExistsError:
        if not stat.S_ISDIR(os.lstat(launcher_dir).st_mode):
            raise SimConfigError(SimConfigErrorCode.INVALID_PATH) from None
    descriptor = os.open(launcher_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, _LAUNCHER_DIR_MODE)
    finally:
        os.close(descriptor)
    return launcher_dir


def _announce(simulator: Simulator, config: SimulatorConfig) -> None:
    sys.stdout.write(
        f"issuer={simulator.issuer_origin} discovery={simulator.discovery_url} "
        f"socket={config.socket_path}\n"
    )
    sys.stdout.flush()


def _wait_for_stop_signal() -> None:
    """Block until SIGINT or SIGTERM, then put the previous handlers back."""
    stop = threading.Event()

    def handle(signum: int, frame: object) -> None:
        stop.set()

    previous = {signum: signal.signal(signum, handle) for signum in _STOP_SIGNALS}
    try:
        stop.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _serve(options: argparse.Namespace) -> int:
    configure_logging(sys.stderr, logging.WARNING)
    socket_path: Path = options.socket
    config = SimulatorConfig(
        state_dir=options.state_dir,
        socket_path=socket_path,
        token_file_path=socket_path.parent / DEFAULT_TOKEN_FILE_NAME,
        launch=LaunchConfig(
            options.image_reference, options.image_digest, tuple(options.arg), tuple(options.env)
        ),
        audience=options.audience,
        issuer_host=options.issuer_host,
        issuer_port=options.issuer_port,
        signers_required=options.signers_required,
        allow_non_loopback=options.allow_non_loopback,
    )
    with Simulator(config) as simulator:
        _announce(simulator, config)
        _wait_for_stop_signal()
    return 0


def _up(options: argparse.Namespace) -> int:
    configure_logging(sys.stderr, logging.WARNING)
    runtime = ContainerRuntime(options.runtime)
    digest = runtime.image_digest(options.image)
    launcher_dir = _launcher_dir(options.state_dir.resolve())
    config = SimulatorConfig(
        state_dir=launcher_dir.parent,
        socket_path=launcher_dir / LAUNCHER_SOCKET_NAME,
        token_file_path=launcher_dir / DEFAULT_TOKEN_FILE_NAME,
        launch=LaunchConfig(options.image, digest, tuple(options.arg), tuple(options.env)),
        audience=options.audience,
        issuer_port=options.issuer_port,
        signers_required=options.signers_required,
    )
    with Simulator(config) as simulator:
        _announce(simulator, config)
        return runtime.run_workload(
            options.image, launcher_dir=launcher_dir, args=options.arg, env=options.env
        )


def _check_vectors_out(out: Path) -> None:
    """The output tree is real directories and regular files: nothing is written via a symlink."""
    directories = (out, out / _SUITE_PATH.parent, out / _CORPUS_PATH.parent)
    files = (out / _SUITE_PATH, out / _CORPUS_PATH)
    for path, kind in [
        *((d, stat.S_ISDIR) for d in directories),
        *((f, stat.S_ISREG) for f in files),
    ]:
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            continue
        if not kind(mode):
            raise SimConfigError(SimConfigErrorCode.INVALID_PATH)


def _vectors(options: argparse.Namespace) -> int:
    _check_vectors_out(options.out)
    suite = generate_suite(options.out)
    corpus = generate_corpus(options.out, seed=_CORPUS_SEED, count=_CORPUS_COUNT)
    sys.stdout.write(f"{suite}\n{corpus}\n")
    return 0


type _Handler = Callable[[argparse.Namespace], int]
type _Commands = argparse._SubParsersAction[_Parser]


def _command(commands: _Commands, name: str, handler: _Handler) -> argparse.ArgumentParser:
    command = commands.add_parser(name, allow_abbrev=False)
    command.add_argument("--state-dir", type=Path, default=Path(DEFAULT_STATE_DIR))
    command.set_defaults(handler=handler)
    return command


def _simulator_command(
    commands: _Commands, name: str, handler: _Handler
) -> argparse.ArgumentParser:
    """Options `serve` and `up` share: the audience, the launch config and the simulator limits."""
    command = _command(commands, name, handler)
    command.add_argument("--audience", type=_text, required=True)
    command.add_argument("--arg", type=_text, action="append", default=[])
    command.add_argument("--env", type=_env, action="append", default=[])
    command.add_argument("--issuer-port", type=_decimal, default=DEFAULT_ISSUER_PORT)
    command.add_argument("--signers-required", type=_decimal, default=DEFAULT_SIGNERS_REQUIRED)
    return command


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="teecustody-sim", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    token = _command(commands, "token", _token)
    token.add_argument("--audience", type=_text, required=True)
    token.add_argument("--nonce", type=_text, action="append", default=[])
    alteration = token.add_mutually_exclusive_group()
    alteration.add_argument("--alter", type=_text)
    alteration.add_argument("--drop", type=_text)
    alteration.add_argument("--case", type=_text)
    serve = _simulator_command(commands, "serve", _serve)
    serve.add_argument("--socket", type=Path, required=True)
    serve.add_argument("--image-reference", type=_text, required=True)
    serve.add_argument("--image-digest", type=_text, required=True)
    serve.add_argument("--issuer-host", type=_text, default=DEFAULT_ISSUER_HOST)
    serve.add_argument("--allow-non-loopback", action="store_true")
    up = _simulator_command(commands, "up", _up)
    up.add_argument("--image", type=_text, required=True)
    up.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    _command(commands, "profile", _profile).add_argument("--out", type=Path, required=True)
    _command(commands, "vectors", _vectors).add_argument("--out", type=Path, required=True)
    return parser


def _error_line(error: Exception) -> tuple[str, int]:
    """The one stderr line and exit status for `error`: a stable code, never exception text."""
    if isinstance(error, SimConfigError):
        return error.code.value, 2
    if type(error) is ValueError and _ERROR_CODE.fullmatch(str(error)):
        return str(error), 2
    return _INTERNAL, 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(argv)
    except _UsageError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    try:
        code: int = options.handler(options)
    except Exception as error:  # noqa: BLE001 - every failure is reduced to a code line
        line, status = _error_line(error)
        sys.stderr.write(f"{line}\n")
        return status
    return code
