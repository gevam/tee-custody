"""`teecustody-sim` command line."""

import argparse
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, NoReturn

from teecustody_sim.config import LaunchConfig, SimConfigError, SimConfigErrorCode
from teecustody_sim.constants import DEFAULT_STATE_DIR, DEFAULT_TOKEN_MAX_AGE_S
from teecustody_sim.keys import SimKeys
from teecustody_sim.profile import build_trust_profile
from teecustody_sim.token import TokenMinter, parse_alteration

_STATE_FILE_NAME: Final = "sim-state.json"
_USAGE_ERROR: Final = "INVALID_ARGUMENT"
_PROFILE_FILE_MODE: Final = 0o644


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
    text = json.dumps(profile, indent=2, sort_keys=True) + "\n"
    descriptor = os.open(
        options.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, _PROFILE_FILE_MODE
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(descriptor, _PROFILE_FILE_MODE)
        handle.write(text)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="teecustody-sim")
    commands = parser.add_subparsers(dest="command", required=True)
    token = commands.add_parser("token")
    token.add_argument("--state-dir", type=Path, default=Path(DEFAULT_STATE_DIR))
    token.add_argument("--audience", type=_text, required=True)
    token.add_argument("--nonce", type=_text, action="append", default=[])
    alteration = token.add_mutually_exclusive_group()
    alteration.add_argument("--alter", type=_text)
    alteration.add_argument("--drop", type=_text)
    alteration.add_argument("--case", type=_text)
    token.set_defaults(handler=_token)
    profile = commands.add_parser("profile")
    profile.add_argument("--state-dir", type=Path, default=Path(DEFAULT_STATE_DIR))
    profile.add_argument("--out", type=Path, required=True)
    profile.set_defaults(handler=_profile)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        options = _parser().parse_args(argv)
    except _UsageError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    try:
        code: int = options.handler(options)
    except (SimConfigError, ValueError) as error:
        sys.stderr.write(f"{error}\n")
        return 2
    return code
