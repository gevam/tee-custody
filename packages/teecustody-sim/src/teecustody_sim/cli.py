"""`teecustody-sim` command line."""

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import DEFAULT_STATE_DIR, DEFAULT_TOKEN_MAX_AGE_S
from teecustody_sim.keys import SimKeys
from teecustody_sim.token import TokenMinter

_STATE_FILE_NAME: Final = "sim-state.json"


def _launch(document: dict[str, Any]) -> LaunchConfig:
    launch = document["launch"]
    return LaunchConfig(
        image_reference=launch["image_reference"],
        image_digest=launch["image_digest"],
        args=tuple(launch["args"]),
        env=tuple(launch["env"].items()),
    )


def _token(options: argparse.Namespace) -> int:
    state_dir: Path = options.state_dir
    document = json.loads((state_dir / _STATE_FILE_NAME).read_text(encoding="utf-8"))
    keys = SimKeys.load_or_create(state_dir, document["signers_required"])
    minter = TokenMinter(
        keys,
        _launch(document),
        ttl_s=document["token_ttl_s"],
        token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S,
    )
    token = minter.mint(options.audience, options.nonce, int(time.time()))
    sys.stdout.write(token + "\n")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="teecustody-sim")
    commands = parser.add_subparsers(dest="command", required=True)
    token = commands.add_parser("token")
    token.add_argument("--state-dir", type=Path, default=Path(DEFAULT_STATE_DIR))
    token.add_argument("--audience", required=True)
    token.add_argument("--nonce", action="append", default=[])
    token.set_defaults(handler=_token)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    code: int = options.handler(options)
    return code
