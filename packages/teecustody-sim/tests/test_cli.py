"""T-16: the `teecustody-sim` command line (API.md §C CLI; PROJECT.md §4.2; spec §15)."""

import base64
import json
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from teecustody_sim import LaunchConfig, Simulator, SimulatorConfig
from teecustody_sim.cli import main

AUDIENCE = "https://cli.teecustody.test/tee"
NONCE = "c3" * 32
LAUNCH = LaunchConfig(
    image_reference="localhost/teecustody-t16:1",
    image_digest="sha256:" + "fedcba9876543210" * 4,
    args=("/app/workload",),
    env=(("PYTHONUNBUFFERED", "1"),),
)

type Cli = Callable[..., tuple[int, str, str]]


def _short_dir(prefix: str) -> Path:
    """AF_UNIX paths are limited to about 100 bytes, so sockets live under a short /tmp path."""
    return Path(tempfile.mkdtemp(prefix=prefix, dir="/tmp"))


def _segment(text: str) -> dict[str, Any]:
    value = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    assert isinstance(value, dict)
    return value


def _payload(token: str) -> dict[str, Any]:
    return _segment(token.split(".")[1])


@pytest.fixture(scope="module")
def state_dir() -> Iterator[Path]:
    """A state directory written by a real T-08 `Simulator` (stopped after it wrote the state)."""
    root = _short_dir("t16s")
    config = SimulatorConfig(
        state_dir=root / "state",
        socket_path=root / "l.sock",
        token_file_path=root / "token",
        launch=LAUNCH,
        audience=AUDIENCE,
        issuer_port=0,
    )
    try:
        with Simulator(config, environ={}):
            pass
        yield config.state_dir
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def run(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return run


def test_token_prints_one_jws_bound_to_the_audience_and_nonce(cli: Cli, state_dir: Path) -> None:
    code, out, err = cli(
        "token", "--state-dir", str(state_dir), "--audience", AUDIENCE, "--nonce", NONCE
    )

    assert (code, err) == (0, "")
    assert out.endswith("\n")
    assert out.count("\n") == 1
    claims = _payload(out.strip())
    assert claims["aud"] == AUDIENCE
    assert claims["eat_nonce"] == NONCE


def _token_args(state_dir: Path, *extra: str) -> list[str]:
    return [
        "token",
        "--state-dir",
        str(state_dir),
        "--audience",
        AUDIENCE,
        "--nonce",
        NONCE,
        *extra,
    ]


@pytest.mark.parametrize(
    ("flags", "claim", "expected"),
    [
        (("--case", "dbgstat_enabled"), "dbgstat", "enabled"),
        (("--alter", "secboot=false"), "secboot", False),
        (("--drop", "eat_nonce"), "eat_nonce", KeyError),
    ],
)
def test_token_applies_the_requested_alteration(
    cli: Cli, state_dir: Path, flags: tuple[str, str], claim: str, expected: object
) -> None:
    code, out, err = cli(*_token_args(state_dir, *flags))

    assert (code, err) == (0, "")
    assert _payload(out.strip()).get(claim, KeyError) == expected


@pytest.mark.parametrize(
    "flags",
    [
        ("--case", "dbgstat_enabled", "--alter", "secboot=false"),
        ("--alter", "secboot=false", "--drop", "eat_nonce"),
        ("--drop", "eat_nonce", "--case", "dbgstat_enabled"),
    ],
)
def test_token_rejects_two_alterations_with_exit_2(
    cli: Cli, state_dir: Path, flags: tuple[str, ...]
) -> None:
    code, out, err = cli(*_token_args(state_dir, *flags))

    assert code == 2
    assert out == ""
    assert err.count("\n") == 1
