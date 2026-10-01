"""T-16: the `teecustody-sim` command line (API.md §C CLI; PROJECT.md §4.2; spec §15)."""

import base64
import json
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from teecustody_sim import JsonValue, LaunchConfig, SimKeys, Simulator, SimulatorConfig
from teecustody_sim import cli as cli_module
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


def _signers(state_dir: Path) -> tuple[Any, ...]:
    return SimKeys.load_or_create(state_dir, 2).signers


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


def test_token_without_state_reports_state_not_initialised(cli: Cli, tmp_path: Path) -> None:
    missing = tmp_path / "no-state"

    code, out, err = cli("token", "--state-dir", str(missing), "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "STATE_NOT_INITIALISED\n")
    assert not missing.exists()


@pytest.mark.parametrize(
    ("flags", "expected_err"),
    [
        (("--case", "nope"), "INVALID_ALTERATION\n"),
        (("--alter", "noequals"), "INVALID_ALTERATION\n"),
        (("--drop", "Bad.Path"), "INVALID_ALTERATION\n"),
        (("--nonce", "short"), "INVALID_NONCE\n"),
    ],
)
def test_token_rejects_invalid_values_with_a_single_code_line(
    cli: Cli, state_dir: Path, flags: tuple[str, str], expected_err: str
) -> None:
    code, out, err = cli("token", "--state-dir", str(state_dir), "--audience", AUDIENCE, *flags)

    assert (code, out, err) == (2, "", expected_err)


@pytest.mark.parametrize(
    "flags",
    [
        ("--audience", "https://cli.teecustody.test/\udcff"),
        ("--audience", AUDIENCE, "--alter", "dbgstat=\ud800"),
        ("--audience", AUDIENCE, "--nonce", "\udcff" * 32),
    ],
)
def test_token_rejects_text_that_is_not_utf8(
    cli: Cli, state_dir: Path, flags: tuple[str, ...]
) -> None:
    # argv bytes that are not UTF-8 reach Python as lone surrogates (surrogateescape).
    code, out, err = cli("token", "--state-dir", str(state_dir), *flags)

    assert code == 2
    assert out == ""
    assert err.count("\n") == 1
    assert "\\" not in err
    assert "\udcff" not in err


class RecordingProfileBuilder:
    """Stands in for T-17 `build_trust_profile`."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dict[str, JsonValue]:
        self.calls.append(kwargs)
        return {"profile_kind": "development", "nested": {"b": [1, 2], "a": None}}


def test_profile_writes_the_built_profile_from_the_state_values(
    cli: Cli, state_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = RecordingProfileBuilder()
    monkeypatch.setattr(cli_module, "build_trust_profile", builder)
    out_file = tmp_path / "dev-profile.json"
    state = json.loads((state_dir / "sim-state.json").read_text())

    code, out, err = cli("profile", "--state-dir", str(state_dir), "--out", str(out_file))

    assert (code, out, err) == (0, "", "")
    [call] = builder.calls
    assert set(call) == {
        "discovery_url",
        "jwks_origin",
        "expected_audience",
        "launch",
        "signers",
        "signers_required",
    }
    assert call["discovery_url"] == state["discovery_url"]
    assert call["jwks_origin"] == state["jwks_origin"]
    assert call["expected_audience"] == AUDIENCE
    assert call["launch"] == LAUNCH
    assert call["signers_required"] == state["signers_required"] == 2
    expected_ids = [signer.key_id for signer in _signers(state_dir)]
    assert [signer.key_id for signer in call["signers"]] == expected_ids
    assert out_file.read_text() == json.dumps(builder(), indent=2, sort_keys=True) + "\n"
    assert stat.S_IMODE(out_file.stat().st_mode) == 0o644


class RecordingGenerator:
    """Stands in for T-17 `generate_suite` / `generate_corpus`."""

    def __init__(self, name: str, calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]]) -> None:
        self._name = name
        self._calls = calls

    def __call__(self, *args: Any, **kwargs: Any) -> Path:
        self._calls.append((self._name, args, kwargs))
        return Path("/generated") / self._name


def test_vectors_generates_suite_then_corpus_and_prints_both_paths(
    cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(cli_module, "generate_suite", RecordingGenerator("suite", calls))
    monkeypatch.setattr(cli_module, "generate_corpus", RecordingGenerator("corpus", calls))
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "vec"

    code, out, err = cli("vectors", "--out", str(out_dir))

    assert (code, err) == (0, "")
    assert calls == [
        ("suite", (out_dir,), {}),
        ("corpus", (out_dir,), {"seed": 1, "count": 512}),
    ]
    assert out == "/generated/suite\n/generated/corpus\n"
    assert not (tmp_path / ".teecustody-sim").exists()
