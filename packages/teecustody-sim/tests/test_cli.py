"""T-16: the `teecustody-sim` command line (API.md §C CLI; PROJECT.md §4.2; spec §15)."""

import base64
import json
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from teecustody.attest import ConfidentialSpaceLauncher
from teecustody_sim import (
    NEGATIVE_CASES,
    ContainerRuntime,
    JsonValue,
    LaunchConfig,
    SimKeys,
    Simulator,
    SimulatorConfig,
)
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


@pytest.fixture(autouse=True)
def _restore_library_logging() -> Iterator[None]:
    """`serve`/`up` configure the library logger; later tests get the previous state back."""
    base = logging.getLogger("teecustody")
    handlers, level = list(base.handlers), base.level
    try:
        yield
    finally:
        base.handlers[:] = handlers
        base.setLevel(level)


@pytest.fixture
def short_dir() -> Iterator[Path]:
    root = _short_dir("t16u")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def clean_environ(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Spec §15.5: the simulator refuses to start next to production credentials."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in ("CLOUDSDK_CONFIG", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(name, raising=False)


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


PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
PRIVATE_JWK_MEMBER_TEXT = re.compile(r'"(?:d|p|q|dp|dq|qi|oth|k)"\s*:')
# A compact JWS whose header and payload are JSON objects ('{"' encodes to "eyJ").
JWS = re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")


def _json_members(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_json_members(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_json_members(item) for item in value))
    return set()


def assert_no_key_material(*texts: str) -> None:
    """SR-7: no PEM private key and no private JWK member, also inside any JWS printed."""
    for text in texts:
        assert "PRIVATE KEY" not in text
        assert PRIVATE_JWK_MEMBER_TEXT.search(text) is None
        for token in JWS.findall(text):
            header, payload = token.split(".")[:2]
            for segment in (header, payload):
                assert not _json_members(_segment(segment)) & PRIVATE_JWK_MEMBERS


def attacker_key_texts(state_dir: Path) -> list[str]:
    """Every text form of the state directory's attacker key (L-1), or none if it has none."""
    path = state_dir / "keys" / "attacker-issuer.pem"
    if not path.exists():
        return []
    pem = path.read_text()
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    n = key.public_key().public_numbers().n
    n_bytes = n.to_bytes(256, "big")
    body = "".join(pem.splitlines()[1:-1])
    return [
        body[:64],
        base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode()[:64],
        base64.b64encode(n_bytes).decode()[:64],
        f"{n:x}"[:64],
        str(n)[:64],
    ]


def assert_no_attacker_key(argv: Sequence[str], *texts: str) -> None:
    """S6 (L-1): no CLI output names the attacker key of the state directory it used."""
    state_dir = Path(argv[argv.index("--state-dir") + 1]) if "--state-dir" in argv else None
    for needle in attacker_key_texts(state_dir) if state_dir is not None else []:
        for text in texts:
            assert needle not in text


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    """Runs `main` and checks every invocation's stdout and stderr for key material (SR-7, L-1)."""

    def run(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        captured = capsys.readouterr()
        assert_no_key_material(captured.out, captured.err)
        assert_no_attacker_key(argv, captured.out, captured.err)
        return code, captured.out, captured.err

    return run


def test_token_prints_one_jws_bound_to_the_audience_and_nonce(cli: Cli, state_dir: Path) -> None:
    # The flag's audience, not the one recorded in the state dir, is the token's `aud`.
    requested = "https://requested.teecustody.test/other"
    assert json.loads((state_dir / "sim-state.json").read_text())["audience"] != requested

    code, out, err = cli(
        "token", "--state-dir", str(state_dir), "--audience", requested, "--nonce", NONCE
    )

    assert (code, err) == (0, "")
    assert out.endswith("\n")
    assert out.count("\n") == 1
    claims = _payload(out.strip())
    assert claims["aud"] == requested
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
        "jwks_uri",
        "expected_audience",
        "launch",
        "signers",
        "signers_required",
    }
    assert call["jwks_uri"] == state["jwks_uri"]
    assert call["expected_audience"] == AUDIENCE
    assert call["launch"] == LAUNCH
    assert call["signers_required"] == state["signers_required"] == 2
    expected_ids = [signer.key_id for signer in _signers(state_dir)]
    assert [signer.key_id for signer in call["signers"]] == expected_ids
    assert out_file.read_text() == json.dumps(builder(), indent=2, sort_keys=True) + "\n"
    assert stat.S_IMODE(out_file.stat().st_mode) == 0o644
    assert_no_key_material(out_file.read_text())


@pytest.mark.usefixtures("clean_environ")
def test_profile_from_a_running_simulator_is_v2_with_its_exact_jwks_uri(
    cli: Cli, short_dir: Path
) -> None:
    """S2: `profile` pins `simulator.jwks_uri`; there is no discovery_url and no jwks_origin."""
    config = SimulatorConfig(
        state_dir=short_dir / "state",
        socket_path=short_dir / "l.sock",
        token_file_path=short_dir / "token",
        launch=LAUNCH,
        audience=AUDIENCE,
        issuer_port=0,
    )
    out_file = short_dir / "dev-profile.json"
    with Simulator(config, environ={}) as simulator:
        code, out, err = cli(
            "profile", "--state-dir", str(config.state_dir), "--out", str(out_file)
        )
        jwks_uri = simulator.jwks_uri

    assert (code, out, err) == (0, "", "")
    profile = json.loads(out_file.read_text())
    assert profile["profile_version"] == 2
    assert profile["jwks_uri"] == jwks_uri
    assert "discovery_url" not in profile
    assert "jwks_origin" not in profile
    assert len(profile) == 13
    for needle in attacker_key_texts(config.state_dir):
        assert needle not in out_file.read_text()


GENERATED_OUTPUTS = {
    "suite": Path("attestation", "suite.cbor"),
    "corpus": Path("wire", "differential-corpus.json"),
    "channel": Path("channel", "suite.cbor"),  # INC-2-API §5.3 (A-4)
}


class RecordingGenerator:
    """Stands in for `generate_suite`, `generate_corpus` and `generate_channel_suite`."""

    def __init__(self, name: str, calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]]) -> None:
        self._name = name
        self._calls = calls

    def __call__(self, out_dir: Path, **kwargs: Any) -> Path:
        self._calls.append((self._name, (out_dir,), kwargs))
        path = out_dir / GENERATED_OUTPUTS[self._name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self._name.encode())
        return path


def test_vectors_generates_attestation_corpus_and_channel_and_prints_three_paths(
    cli: Cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(cli_module, "generate_suite", RecordingGenerator("suite", calls))
    monkeypatch.setattr(cli_module, "generate_corpus", RecordingGenerator("corpus", calls))
    monkeypatch.setattr(cli_module, "generate_channel_suite", RecordingGenerator("channel", calls))
    monkeypatch.chdir(tmp_path)
    out_dir = tmp_path / "vec"

    code, out, err = cli("vectors", "--out", str(out_dir))

    assert (code, err) == (0, "")
    [staging] = {args[0] for _, args, _ in calls}
    assert staging.parent == out_dir
    assert calls == [
        ("suite", (staging,), {}),
        ("corpus", (staging,), {"seed": 1, "count": 512}),
        ("channel", (staging,), {}),
    ]
    suite, corpus, channel = (out_dir / path for path in GENERATED_OUTPUTS.values())
    assert out == f"{suite}\n{corpus}\n{channel}\n"
    assert (suite.read_bytes(), corpus.read_bytes(), channel.read_bytes()) == (
        b"suite",
        b"corpus",
        b"channel",
    )
    assert sorted(out_dir.rglob("*")) == sorted(
        {suite, corpus, channel, suite.parent, corpus.parent, channel.parent}
    )
    assert not (tmp_path / ".teecustody-sim").exists()


IMAGE = "localhost/teecustody-t16-up:2"
IMAGE_ID = "sha256:" + "5a" * 32


class FakeContainerRunner:
    """Answers `image inspect`; on `run`, calls the launcher socket the way the workload would."""

    def __init__(self, *, inspect_stdout: str = IMAGE_ID + "\n", exit_code: int = 5) -> None:
        self.calls: list[list[str]] = []
        self.seen_inside: dict[str, Any] = {}
        self.inspect_stdout = inspect_stdout
        self.exit_code = exit_code

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[1] == "image":
            return subprocess.CompletedProcess(list(argv), 0, self.inspect_stdout, "")
        mount_source = Path(argv[argv.index("-v") + 1].split(":")[0])
        launcher = ConfidentialSpaceLauncher(
            str(mount_source / "teeserver.sock"), timeout_s=5.0, max_response_bytes=65536
        )
        token = launcher.get_attestation_token(AUDIENCE, "OIDC", bytes(32))
        self.seen_inside["claims"] = _payload(token.value)
        self.seen_inside["token_file"] = (
            mount_source / "attestation_verifier_claims_token"
        ).exists()
        self.seen_inside["mode"] = stat.S_IMODE(mount_source.stat().st_mode)
        return subprocess.CompletedProcess(list(argv), self.exit_code, None, None)


@pytest.fixture
def fake_runner(monkeypatch: pytest.MonkeyPatch) -> FakeContainerRunner:
    runner = FakeContainerRunner()

    def runtime(executable: Any) -> ContainerRuntime:
        return ContainerRuntime(executable, run=runner)

    monkeypatch.setattr(cli_module, "ContainerRuntime", runtime)
    return runner


@pytest.mark.usefixtures("clean_environ")
def test_up_runs_the_image_against_a_live_launcher_and_returns_its_exit_code(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOST_ONLY_SECRET", "host-value")
    state = short_dir / "state"

    code, out, err = cli(
        "up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE,
        "--runtime", "podman", "--arg", "/app/workload", "--arg", "two words",
        "--env", "MODE=test", "--env", "WITH_EQUALS=a=b", "--issuer-port", "0",
    )  # fmt: skip

    launcher_dir = state.resolve() / "launcher"
    assert (code, err) == (5, "")
    assert fake_runner.calls == [
        ["podman", "image", "inspect", "--format", "{{.Id}}", IMAGE],
        [
            "podman", "run", "--rm", "--network", "none",
            "-v", f"{launcher_dir}:/run/container_launcher",
            "-e", "MODE=test", "-e", "WITH_EQUALS=a=b",
            IMAGE, "/app/workload", "two words",
        ],
    ]  # fmt: skip
    assert not any("host-value" in part for call in fake_runner.calls for part in call)
    claims = fake_runner.seen_inside["claims"]
    assert claims["aud"] == AUDIENCE
    assert claims["submods"]["container"]["image_digest"] == IMAGE_ID
    assert claims["submods"]["container"]["image_reference"] == IMAGE
    assert claims["submods"]["container"]["args"] == ["/app/workload", "two words"]
    assert claims["submods"]["container"]["env"] == {"MODE": "test", "WITH_EQUALS": "a=b"}
    assert fake_runner.seen_inside["token_file"] is True
    assert fake_runner.seen_inside["mode"] == 0o755
    [line] = out.splitlines()
    assert line.startswith("issuer=http://127.0.0.1:")
    assert line.endswith(f" socket={launcher_dir / 'teeserver.sock'}")
    assert not (launcher_dir / "teeserver.sock").exists()


@pytest.mark.usefixtures("clean_environ")
def test_up_with_a_bad_inspect_output_exits_2_before_serving_or_running(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner
) -> None:
    fake_runner.inspect_stdout = "Error: no such image\n"
    state = short_dir / "state"

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "INVALID_LAUNCH_CONFIG\n")
    assert [call[1] for call in fake_runner.calls] == ["image"]
    assert not state.exists()


@pytest.mark.parametrize(
    "flags",
    [
        ("--env", "NOEQUALS"),
        ("--env", "=x"),
        ("--env", "BAD=\udcff"),
        ("--arg", "\udcff"),
        ("--image", "\udcff"),
        ("--runtime", "sh"),
        ("--issuer-port", "-1"),
        ("--issuer-port", "٣"),
        ("--signers-required", " 2"),
        ("--signers-required", "+2"),
        ("--audi", AUDIENCE),
    ],
)
def test_up_rejects_invalid_arguments_with_a_single_code_line(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner, flags: tuple[str, str]
) -> None:
    code, out, err = cli(
        "up", "--state-dir", str(short_dir / "state"), "--image", IMAGE, "--audience", AUDIENCE,
        *flags,
    )  # fmt: skip

    assert (code, out, err) == (2, "", "INVALID_ARGUMENT\n")
    assert fake_runner.calls == []
    assert not (short_dir / "state").exists()


@pytest.mark.usefixtures("clean_environ")
def test_up_accepts_an_env_entry_with_an_empty_value(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner
) -> None:
    code, _, err = cli("up", "--state-dir", str(short_dir / "state"), "--image", IMAGE,
                       "--audience", AUDIENCE, "--env", "EMPTY=", "--issuer-port", "0")  # fmt: skip

    assert (code, err) == (5, "")
    assert fake_runner.seen_inside["claims"]["submods"]["container"]["env"] == {"EMPTY": ""}


@pytest.mark.usefixtures("clean_environ")
def test_up_makes_an_existing_launcher_dir_0755(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner
) -> None:
    state = short_dir / "state"
    (state / "launcher").mkdir(mode=0o700, parents=True)
    state.chmod(0o700)

    code, _, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE,
                       "--issuer-port", "0")  # fmt: skip

    assert (code, err) == (5, "")
    assert fake_runner.seen_inside["mode"] == 0o755


@pytest.mark.usefixtures("clean_environ")
def test_up_refuses_a_launcher_dir_that_is_a_symlink(
    cli: Cli, short_dir: Path, fake_runner: FakeContainerRunner
) -> None:
    state = short_dir / "state"
    state.mkdir(mode=0o700)
    elsewhere = short_dir / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (state / "launcher").symlink_to(elsewhere)

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "INVALID_PATH\n")
    assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o700
    assert [call[1] for call in fake_runner.calls] == ["image"]


def _state_dir_under_a_file(root: Path) -> Path:
    (root / "a-file").write_text("not a directory")
    return root / "a-file" / "state"


def _state_dir_is_a_file(root: Path) -> Path:
    (root / "state").write_text("not a directory")
    return root / "state"


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize("make_state", [_state_dir_under_a_file, _state_dir_is_a_file])
def test_up_reports_a_state_dir_that_cannot_be_created_as_invalid_path(
    cli: Cli,
    short_dir: Path,
    fake_runner: FakeContainerRunner,
    make_state: Callable[[Path], Path],
) -> None:
    state = make_state(short_dir)

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "INVALID_PATH\n")
    assert [call[1] for call in fake_runner.calls] == ["image"]


class RecordingSignals:
    """Stands in for `signal.signal`: real handlers cannot be set outside the main thread."""

    def __init__(self) -> None:
        self.installed: list[tuple[int, Any]] = []
        self.handlers: dict[int, Callable[[int, object], None]] = {}

    def __call__(self, signum: int, handler: Any) -> Any:
        self.installed.append((signum, handler))
        if callable(handler):
            self.handlers[signum] = handler
        return signal.SIG_DFL


def _wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 10.0
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.01)


def _serve_until_signal(
    argv: list[str],
    signals: RecordingSignals,
    signum: int,
    while_serving: Callable[[], None] = lambda: None,
) -> int | None:
    """Run `main(argv)` in a thread, call `while_serving`, then deliver `signum` to `serve`."""
    signals.handlers.clear()
    result: list[int] = []
    thread = threading.Thread(target=lambda: result.append(main(argv)))
    thread.start()
    try:
        _wait_until(lambda: not thread.is_alive() or signum in signals.handlers)
        while_serving()
    finally:
        if signum in signals.handlers:
            signals.handlers[signum](signum, None)
        thread.join(timeout=10.0)
    assert not thread.is_alive()
    return result[0] if result else None


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_serve_runs_until_a_signal_then_stops_and_removes_the_socket(
    capsys: pytest.CaptureFixture[str],
    short_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    signum: int,
) -> None:
    signals = RecordingSignals()
    monkeypatch.setattr(signal, "signal", signals)
    socket_path = short_dir / "teeserver.sock"
    argv = [
        "serve", "--state-dir", str(short_dir / "state"), "--socket", str(socket_path),
        "--audience", AUDIENCE, "--image-reference", LAUNCH.image_reference,
        "--image-digest", LAUNCH.image_digest, "--arg", "/app/workload", "--env", "MODE=test",
        "--issuer-port", "0",
    ]  # fmt: skip
    claims: dict[str, Any] = {}

    def request_a_token() -> None:
        _wait_until(socket_path.exists)  # handlers are installed before the simulator starts
        launcher = ConfidentialSpaceLauncher(
            str(socket_path), timeout_s=5.0, max_response_bytes=65536
        )
        token = launcher.get_attestation_token(AUDIENCE, "OIDC", bytes(32))
        claims.update(_payload(token.value))

    assert _serve_until_signal(argv, signals, signum, request_a_token) == 0

    captured = capsys.readouterr()
    assert_no_key_material(captured.out, captured.err)
    assert captured.err == ""
    [line] = captured.out.splitlines()
    issuer, discovery, socket_field = line.split(" ")
    origin = issuer.removeprefix("issuer=")
    assert origin.startswith("http://127.0.0.1:")
    assert discovery == f"discovery={origin}/.well-known/openid-configuration"
    assert socket_field == f"socket={socket_path}"
    assert claims["aud"] == AUDIENCE
    assert claims["submods"]["container"]["args"] == ["/app/workload"]
    assert claims["submods"]["container"]["env"] == {"MODE": "test"}
    assert (short_dir / "attestation_verifier_claims_token").exists()
    assert not socket_path.exists()
    restored = [entry for entry in signals.installed if entry[1] is signal.SIG_DFL]
    assert sorted(signum for signum, _ in restored) == sorted([signal.SIGINT, signal.SIGTERM])


def _serve_argv(short_dir: Path, *extra: str) -> list[str]:
    return [
        "serve", "--state-dir", str(short_dir / "state"), "--socket", str(short_dir / "s.sock"),
        "--audience", AUDIENCE, "--image-reference", LAUNCH.image_reference,
        "--image-digest", LAUNCH.image_digest, "--issuer-port", "0", *extra,
    ]  # fmt: skip


@pytest.mark.usefixtures("clean_environ")
def test_serve_with_allow_non_loopback_warns_on_stderr_at_every_start(
    capsys: pytest.CaptureFixture[str], short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signals = RecordingSignals()
    monkeypatch.setattr(signal, "signal", signals)
    argv = _serve_argv(short_dir, "--issuer-host", "127.0.0.1", "--allow-non-loopback")
    warnings = []
    for _ in range(2):
        assert _serve_until_signal(argv, signals, signal.SIGTERM) == 0
        captured = capsys.readouterr()
        assert_no_key_material(captured.out, captured.err)
        warnings.append(json.loads(captured.err))

    assert [(w["level"], w["outcome"]) for w in warnings] == [
        ("WARNING", "SIM_NON_LOOPBACK_BIND"),
        ("WARNING", "SIM_NON_LOOPBACK_BIND"),
    ]


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.1", "::"])  # noqa: S104 - refused, never bound
def test_serve_refuses_a_non_loopback_host_without_the_flag(
    cli: Cli, short_dir: Path, host: str
) -> None:
    code, out, err = cli(*_serve_argv(short_dir, "--issuer-host", host))

    assert (code, out, err) == (2, "", "NON_LOOPBACK_NOT_ALLOWED\n")
    assert not (short_dir / "s.sock").exists()


@pytest.mark.usefixtures("clean_environ")
def test_serve_refuses_to_start_next_to_production_credentials(
    cli: Cli, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secret/path/key.json")

    code, out, err = cli(*_serve_argv(short_dir))

    assert (code, out, err) == (2, "", "PRODUCTION_CREDENTIALS_PRESENT\n")
    assert not (short_dir / "s.sock").exists()


@pytest.mark.parametrize(
    "flags",
    [
        ("--env", "NOEQUALS"),
        ("--env", "=x"),
        ("--env", "="),
        ("--env", "=a=b"),
        ("--issuer-host", "\udcff"),
        ("--image-digest", "\udcff"),
        ("--allow-non-loopback=yes",),
        ("--issuer-port", "65536x"),
    ],
)
def test_serve_rejects_invalid_arguments_with_a_single_code_line(
    cli: Cli, short_dir: Path, flags: tuple[str, ...]
) -> None:
    code, out, err = cli(*_serve_argv(short_dir, *flags))

    assert (code, out, err) == (2, "", "INVALID_ARGUMENT\n")
    assert not (short_dir / "state").exists()


class Exploding:
    """Raises an exception whose text must never reach the terminal."""

    def __init__(self, error: BaseException) -> None:
        self._error = error

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        raise self._error


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
        ValueError('{"d": "c2VjcmV0"}'),
        ValueError("INVALID_THING with detail"),
        OSError(13, "Permission denied", "/secret/path"),
        KeyError("d"),
    ],
)
def test_an_unexpected_exception_prints_only_internal_and_exits_1(
    cli: Cli, state_dir: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    monkeypatch.setattr(cli_module, "TokenMinter", Exploding(error))

    code, out, err = cli(*_token_args(state_dir))

    assert (code, out, err) == (1, "", "INTERNAL\n")


@pytest.mark.parametrize("case_id", [case.case_id for case in NEGATIVE_CASES])
def test_every_named_case_token_carries_no_key_material(
    cli: Cli, state_dir: Path, case_id: str
) -> None:
    # The `cli` fixture applies the SR-7 check to stdout and stderr.
    code, out, _ = cli(*_token_args(state_dir, "--case", case_id))

    assert code == 0
    assert JWS.fullmatch(out.strip()) is not None


@pytest.mark.parametrize("case_id", ["jwks_other_path", "jwks_other_path_same_kid"])
def test_token_attacker_cases_are_signed_by_the_state_dir_attacker_key(
    cli: Cli, state_dir: Path, case_id: str
) -> None:
    """Criterion 7 (INC-2-API §16.3): `token --case jwks_other_path*` uses the state dir's key."""
    keys = SimKeys.load_or_create(state_dir, 2)
    code, out, err = cli(*_token_args(state_dir, "--case", case_id))
    header, payload, signature = out.strip().split(".")
    signing_input = f"{header}.{payload}".encode()

    assert (code, err) == (0, "")
    assert base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)) == (
        keys.sign_jws_attacker(signing_input)
    )
    expected_kid = keys.attacker_issuer_kid if case_id == "jwks_other_path" else keys.issuer_kid
    assert _segment(header) == {"alg": "RS256", "kid": expected_kid, "typ": "JWT"}


@pytest.fixture
def recorded_generators(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any, Any]]:
    calls: list[tuple[str, Any, Any]] = []
    monkeypatch.setattr(cli_module, "generate_suite", RecordingGenerator("suite", calls))
    monkeypatch.setattr(cli_module, "generate_corpus", RecordingGenerator("corpus", calls))
    monkeypatch.setattr(cli_module, "generate_channel_suite", RecordingGenerator("channel", calls))
    return calls


def _symlink_out(root: Path) -> Path:
    target = root / "elsewhere"
    target.mkdir()
    out = root / "out"
    out.symlink_to(target)
    return out


def _symlink_subdir(root: Path) -> Path:
    out = root / "out"
    out.mkdir()
    (root / "elsewhere").mkdir()
    (out / "wire").symlink_to(root / "elsewhere")
    return out


def _symlink_file(root: Path) -> Path:
    out = root / "out"
    (out / "attestation").mkdir(parents=True)
    (out / "attestation" / "suite.cbor").symlink_to(root / "victim")
    return out


def _dangling_corpus_link(root: Path) -> Path:
    out = root / "out"
    (out / "wire").mkdir(parents=True)
    (out / "wire" / "differential-corpus.json").symlink_to(root / "missing")
    return out


def _out_is_a_file(root: Path) -> Path:
    out = root / "out"
    out.write_text("not a directory")
    return out


def _subdir_is_a_file(root: Path) -> Path:
    out = root / "out"
    out.mkdir()
    (out / "attestation").write_text("not a directory")
    return out


def _output_is_a_directory(root: Path) -> Path:
    out = root / "out"
    (out / "wire" / "differential-corpus.json").mkdir(parents=True)
    return out


def _symlink_channel_dir(root: Path) -> Path:
    out = root / "out"
    out.mkdir()
    (root / "elsewhere").mkdir()
    (out / "channel").symlink_to(root / "elsewhere")
    return out


def _dangling_channel_link(root: Path) -> Path:
    out = root / "out"
    (out / "channel").mkdir(parents=True)
    (out / "channel" / "suite.cbor").symlink_to(root / "missing")
    return out


def _channel_output_is_a_directory(root: Path) -> Path:
    out = root / "out"
    (out / "channel" / "suite.cbor").mkdir(parents=True)
    return out


@pytest.mark.parametrize(
    "make_out",
    [
        _symlink_out,
        _symlink_subdir,
        _symlink_file,
        _dangling_corpus_link,
        _out_is_a_file,
        _subdir_is_a_file,
        _output_is_a_directory,
        _symlink_channel_dir,
        _dangling_channel_link,
        _channel_output_is_a_directory,
    ],
)
@pytest.mark.parametrize("force", [(), ("--force",)])
def test_vectors_refuses_to_write_through_symlinks_or_onto_non_directories(
    cli: Cli,
    tmp_path: Path,
    recorded_generators: list[tuple[str, Any, Any]],
    make_out: Callable[[Path], Path],
    force: tuple[str, ...],
) -> None:
    out = make_out(tmp_path)

    code, stdout, err = cli("vectors", "--out", str(out), *force)

    assert (code, stdout, err) == (2, "", "INVALID_PATH\n")
    assert recorded_generators == []
    assert not (tmp_path / "victim").exists()
    assert not any((tmp_path / "elsewhere").glob("*"))


def _out_under_an_unsearchable_parent(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    parent = root / "unsearchable"
    parent.mkdir(mode=0o600)
    if os.geteuid() == 0:  # root ignores directory modes: the OS error is injected instead
        real_lstat = os.lstat

        def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if Path(path).is_relative_to(parent) and Path(path) != parent:
                raise PermissionError(13, "denied")
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(cli_module.os, "lstat", lstat)
    return parent / "out"


def _out_name_too_long(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return root / ("n" * 300)


def _out_under_a_regular_file(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (root / "a-file").write_text("not a directory")
    return root / "a-file" / "x"


@pytest.mark.parametrize(
    "make_out", [_out_under_an_unsearchable_parent, _out_name_too_long, _out_under_a_regular_file]
)
def test_vectors_reports_an_output_path_it_cannot_inspect_as_invalid_path(
    cli: Cli,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    recorded_generators: list[tuple[str, Any, Any]],
    make_out: Callable[[Path, pytest.MonkeyPatch], Path],
) -> None:
    out = make_out(tmp_path, monkeypatch)
    try:
        code, stdout, err = cli("vectors", "--out", str(out))
    finally:
        for path in tmp_path.iterdir():
            path.chmod(0o700)

    assert (code, stdout, err) == (2, "", "INVALID_PATH\n")
    assert recorded_generators == []


def test_vectors_writes_into_an_existing_real_output_tree(
    cli: Cli, tmp_path: Path, recorded_generators: list[tuple[str, Any, Any]]
) -> None:
    out = tmp_path / "out"
    (out / "attestation").mkdir(parents=True)
    (out / "attestation" / "suite.cbor").write_bytes(b"old")
    (out / "wire").mkdir()

    code, _, err = cli("vectors", "--out", str(out), "--force")

    assert (code, err) == (0, "")
    assert [name for name, _, _ in recorded_generators] == ["suite", "corpus", "channel"]


def _tree(root: Path) -> dict[Path, bytes]:
    return {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}


def _existing_suite(out: Path) -> None:
    (out / "attestation").mkdir(parents=True)
    (out / "attestation" / "suite.cbor").write_bytes(b"approved suite")


def _existing_corpus(out: Path) -> None:
    (out / "wire").mkdir(parents=True)
    (out / "wire" / "differential-corpus.json").write_bytes(b"approved corpus")


def _existing_channel(out: Path) -> None:
    (out / "channel").mkdir(parents=True)
    (out / "channel" / "suite.cbor").write_bytes(b"approved channel suite")


@pytest.mark.parametrize("make_existing", [_existing_suite, _existing_corpus, _existing_channel])
def test_vectors_refuses_to_overwrite_an_existing_output_without_force(
    cli: Cli,
    tmp_path: Path,
    recorded_generators: list[tuple[str, Any, Any]],
    make_existing: Callable[[Path], None],
) -> None:
    out = tmp_path / "out"
    make_existing(out)
    before = _tree(tmp_path)

    code, stdout, err = cli("vectors", "--out", str(out))

    assert (code, stdout, err) == (2, "", "OUTPUT_EXISTS\n")
    assert recorded_generators == []
    assert _tree(tmp_path) == before
    assert sorted(tmp_path.rglob("*")) == sorted({out, *before, *(p.parent for p in before)})


def test_vectors_with_force_regenerates_all_three_existing_outputs(
    cli: Cli, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    _existing_suite(out)
    _existing_corpus(out)
    _existing_channel(out)
    suite, corpus, channel = (out / path for path in GENERATED_OUTPUTS.values())

    code, stdout, err = cli("vectors", "--out", str(out), "--force")

    assert (code, stdout, err) == (0, f"{suite}\n{corpus}\n{channel}\n", "")
    assert suite.read_bytes() != b"approved suite"
    assert corpus.read_bytes() != b"approved corpus"
    assert channel.read_bytes() != b"approved channel suite"
    assert set(_tree(tmp_path)) == {suite, corpus, channel}


def _unwritable_parent(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    parent = root / "read-only"
    parent.mkdir(mode=0o500)
    if os.geteuid() == 0:  # root ignores directory modes: the OS error is injected instead
        monkeypatch.setattr(cli_module, "generate_suite", Exploding(PermissionError(13, "denied")))
    return parent / "out"


def _suite_permission_error(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cli_module, "generate_suite", Exploding(PermissionError(13, "denied")))
    return root / "out"


def _corpus_os_error(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cli_module, "generate_corpus", Exploding(OSError(28, "no space")))
    return root / "out"


def _channel_os_error(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(cli_module, "generate_channel_suite", Exploding(OSError(28, "no space")))
    return root / "out"


@pytest.mark.parametrize(
    "make_out", [_unwritable_parent, _suite_permission_error, _corpus_os_error, _channel_os_error]
)
def test_vectors_reports_an_os_error_while_writing_as_invalid_path(
    cli: Cli,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    make_out: Callable[[Path, pytest.MonkeyPatch], Path],
) -> None:
    out = make_out(tmp_path, monkeypatch)
    try:
        code, stdout, err = cli("vectors", "--out", str(out))
    finally:
        for path in tmp_path.iterdir():
            path.chmod(0o700)

    assert (code, stdout, err) == (2, "", "INVALID_PATH\n")


@pytest.mark.parametrize("failing", ["generate_corpus", "generate_channel_suite"])
@pytest.mark.parametrize(
    ("error", "expected"),
    [(OSError(28, "no space"), "INVALID_PATH\n"), (RuntimeError(), "INTERNAL\n")],
)
def test_vectors_leaves_existing_outputs_untouched_when_a_later_generator_fails(
    cli: Cli,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected: str,
    failing: str,
) -> None:
    out = tmp_path / "out"
    _existing_suite(out)
    _existing_corpus(out)
    _existing_channel(out)
    before = _tree(tmp_path)
    monkeypatch.setattr(cli_module, failing, Exploding(error))

    code, stdout, err = cli("vectors", "--out", str(out), "--force")

    assert (stdout, err) == ("", expected)
    assert code != 0
    assert _tree(tmp_path) == before
    assert sorted(out.rglob("*")) == sorted({*before, *(p.parent for p in before)})


@pytest.fixture
def recorded_profile(monkeypatch: pytest.MonkeyPatch) -> RecordingProfileBuilder:
    builder = RecordingProfileBuilder()
    monkeypatch.setattr(cli_module, "build_trust_profile", builder)
    return builder


@pytest.mark.usefixtures("recorded_profile")
@pytest.mark.parametrize("dangling", [False, True])
def test_profile_never_writes_through_a_symlink(
    cli: Cli, state_dir: Path, tmp_path: Path, dangling: bool
) -> None:
    victim = tmp_path / "victim"
    if not dangling:
        victim.write_text("untouched")
    out_file = tmp_path / "dev-profile.json"
    out_file.symlink_to(victim)

    code, out, err = cli("profile", "--state-dir", str(state_dir), "--out", str(out_file))

    assert (code, out, err) == (2, "", "INVALID_PATH\n")
    assert victim.exists() is not dangling
    if not dangling:
        assert victim.read_text() == "untouched"


@pytest.mark.usefixtures("recorded_profile")
def test_profile_replaces_an_existing_file_and_makes_it_0644(
    cli: Cli, state_dir: Path, tmp_path: Path
) -> None:
    out_file = tmp_path / "dev-profile.json"
    out_file.write_text("x" * 4096)
    out_file.chmod(0o600)

    code, _, err = cli("profile", "--state-dir", str(state_dir), "--out", str(out_file))

    assert (code, err) == (0, "")
    assert json.loads(out_file.read_text())["profile_kind"] == "development"
    assert stat.S_IMODE(out_file.stat().st_mode) == 0o644


@pytest.mark.usefixtures("recorded_profile")
@pytest.mark.parametrize("name", ["missing-dir/dev-profile.json", "is-a-dir"])
def test_profile_reports_an_unusable_output_path_as_invalid_path(
    cli: Cli, state_dir: Path, tmp_path: Path, name: str
) -> None:
    (tmp_path / "is-a-dir").mkdir()

    code, out, err = cli("profile", "--state-dir", str(state_dir), "--out", str(tmp_path / name))

    assert (code, out, err) == (2, "", "INVALID_PATH\n")


def _state_copy(state_dir: Path, tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    copy = tmp_path / "state"
    shutil.copytree(state_dir, copy)
    return copy, json.loads((copy / "sim-state.json").read_text())


def _with(document: dict[str, Any], path: tuple[str, ...], value: object) -> dict[str, Any]:
    edited = json.loads(json.dumps(document))
    parent = edited
    for part in path[:-1]:
        parent = parent[part]
    if value is KeyError:
        del parent[path[-1]]
    else:
        parent[path[-1]] = value
    return edited


MALFORMED_STATE = [
    (("state_version",), 1),
    (("state_version",), 3),
    (("state_version",), True),
    (("state_version",), KeyError),
    (("audience",), 7),
    (("issuer",), None),
    (("jwks_uri",), ["x"]),
    (("jwks_uri",), KeyError),
    (("discovery_url",), "http://127.0.0.1:1/.well-known/openid-configuration"),
    (("jwks_origin",), "http://127.0.0.1:1"),
    (("signers_required",), "2"),
    (("signers_required",), True),
    (("token_ttl_s",), 0),
    (("token_ttl_s",), 1.5),
    (("launch",), "launch"),
    (("launch", "image_reference"), 1),
    (("launch", "image_digest"), KeyError),
    (("launch", "args"), "/app/workload"),
    (("launch", "args"), [1]),
    (("launch", "env"), [["A", "B"]]),
    (("launch", "env"), {"A": 1}),
    (("launch", "extra"), "x"),
    (("extra",), "x"),
]


@pytest.mark.parametrize(("path", "value"), MALFORMED_STATE)
def test_a_malformed_state_file_is_state_not_initialised(
    cli: Cli, state_dir: Path, tmp_path: Path, path: tuple[str, ...], value: object
) -> None:
    copy, document = _state_copy(state_dir, tmp_path)
    (copy / "sim-state.json").write_text(json.dumps(_with(document, path, value)))

    code, out, err = cli("token", "--state-dir", str(copy), "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "STATE_NOT_INITIALISED\n")


@pytest.mark.parametrize("command", ["profile", "token"])
def test_an_inc1_v1_state_file_is_state_not_initialised(
    cli: Cli, state_dir: Path, tmp_path: Path, command: str
) -> None:
    """S5 (ADR 0012): a v1 state file is never read; the developer re-runs `serve`/`up`."""
    copy, document = _state_copy(state_dir, tmp_path)
    origin = document.pop("jwks_uri").removesuffix("/jwks")
    document.update(
        state_version=1,
        discovery_url=origin + "/.well-known/openid-configuration",
        jwks_origin=origin,
    )
    (copy / "sim-state.json").write_text(json.dumps(document))
    out_file = tmp_path / "p.json"
    argv = {"profile": ("--out", str(out_file)), "token": ("--audience", AUDIENCE)}[command]

    code, out, err = cli(command, "--state-dir", str(copy), *argv)

    assert (code, out, err) == (2, "", "STATE_NOT_INITIALISED\n")
    assert not out_file.exists()


@pytest.mark.parametrize("text", ["", "{", "[]", '"state"', "\xff"])
def test_a_state_file_that_is_not_a_json_object_is_state_not_initialised(
    cli: Cli, state_dir: Path, tmp_path: Path, text: str
) -> None:
    copy, _ = _state_copy(state_dir, tmp_path)
    (copy / "sim-state.json").write_bytes(text.encode("latin-1"))

    code, out, err = cli("token", "--state-dir", str(copy), "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "STATE_NOT_INITIALISED\n")


def test_a_symlinked_state_file_is_refused(cli: Cli, state_dir: Path, tmp_path: Path) -> None:
    copy, _ = _state_copy(state_dir, tmp_path)
    real = tmp_path / "real-state.json"
    (copy / "sim-state.json").rename(real)
    (copy / "sim-state.json").symlink_to(real)

    code, out, err = cli("profile", "--state-dir", str(copy), "--out", str(tmp_path / "p.json"))

    assert (code, out, err) == (2, "", "INVALID_PATH\n")
    assert not (tmp_path / "p.json").exists()


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_a_state_path_that_is_not_a_regular_file_is_refused(
    cli: Cli, state_dir: Path, tmp_path: Path, kind: str
) -> None:
    copy, _ = _state_copy(state_dir, tmp_path)
    (copy / "sim-state.json").unlink()
    if kind == "directory":
        (copy / "sim-state.json").mkdir()
    else:
        os.mkfifo(copy / "sim-state.json")

    code, out, err = cli("token", "--state-dir", str(copy), "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "INVALID_PATH\n")


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize(("container_status", "exit_code"), [(0, 0), (1, 1), (-9, 137), (-15, 143)])
def test_up_exits_with_the_shell_status_of_the_container(
    cli: Cli,
    short_dir: Path,
    fake_runner: FakeContainerRunner,
    container_status: int,
    exit_code: int,
) -> None:
    # A runtime killed by a signal reports -N; the shell convention for that status is 128 + N.
    fake_runner.exit_code = container_status

    code, _, err = cli("up", "--state-dir", str(short_dir / "state"), "--image", IMAGE,
                       "--audience", AUDIENCE, "--issuer-port", "0")  # fmt: skip

    assert (code, err) == (exit_code, "")


@pytest.mark.usefixtures("clean_environ")
def test_up_interrupted_by_ctrl_c_stops_the_simulator_and_exits_130_without_a_traceback(
    cli: Cli, short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        if argv[1] == "image":
            return subprocess.CompletedProcess(list(argv), 0, IMAGE_ID + "\n", "")
        raise KeyboardInterrupt

    monkeypatch.setattr(
        cli_module,
        "ContainerRuntime",
        lambda executable: ContainerRuntime(executable, run=interrupted),
    )
    state = short_dir / "state"

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE,
                         "--issuer-port", "0")  # fmt: skip

    assert (code, err) == (130, "")
    assert out.startswith("issuer=")
    assert not (state.resolve() / "launcher" / "teeserver.sock").exists()


@pytest.mark.parametrize("where", ["before", "after"])
def test_a_valid_state_padded_past_64_kib_is_state_not_initialised(
    cli: Cli, state_dir: Path, tmp_path: Path, where: str
) -> None:
    copy, document = _state_copy(state_dir, tmp_path)
    padding = " " * 65536
    text = json.dumps(document)
    (copy / "sim-state.json").write_text(padding + text if where == "before" else text + padding)

    code, out, err = cli("token", "--state-dir", str(copy), "--audience", AUDIENCE)

    assert (code, out, err) == (2, "", "STATE_NOT_INITIALISED\n")


@pytest.mark.usefixtures("clean_environ")
def test_serve_installs_its_stop_handlers_before_starting_and_announcing(
    short_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A SIGTERM sent as soon as the readiness line is read must stop `serve`, not kill it.
    events: list[str] = []
    signals = RecordingSignals()

    def recording_signal(signum: int, handler: Any) -> Any:
        if callable(handler):
            events.append(f"handler:{signal.Signals(signum).name}")
        return signals(signum, handler)

    real_start, real_announce = Simulator.start, cli_module._announce
    monkeypatch.setattr(signal, "signal", recording_signal)
    monkeypatch.setattr(
        Simulator, "start", lambda sim: (events.append("start"), real_start(sim))[1]
    )
    monkeypatch.setattr(
        cli_module, "_announce", lambda *args: (events.append("announce"), real_announce(*args))[1]
    )

    assert _serve_until_signal(_serve_argv(short_dir), signals, signal.SIGTERM) == 0
    assert events == ["handler:SIGINT", "handler:SIGTERM", "start", "announce"]


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize(
    ("state_name", "flags", "expected_err"),
    [
        ("state", ("--env", "1A=x"), "INVALID_LAUNCH_CONFIG\n"),
        ("state", ("--env", "A B=x"), "INVALID_LAUNCH_CONFIG\n"),
        ("state", ("--arg", "nul\0"), "INVALID_LAUNCH_CONFIG\n"),
        ("st:ate", (), "INVALID_PATH\n"),
    ],
)
def test_up_validates_the_launch_and_mount_before_inspecting_or_writing_state(
    cli: Cli,
    short_dir: Path,
    fake_runner: FakeContainerRunner,
    state_name: str,
    flags: tuple[str, ...],
    expected_err: str,
) -> None:
    state = short_dir / state_name

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE,
                         "--issuer-port", "0", *flags)  # fmt: skip

    assert (code, out, err) == (2, "", expected_err)
    assert fake_runner.calls == []
    assert not state.exists()


@pytest.mark.usefixtures("clean_environ")
@pytest.mark.parametrize(
    ("host_env", "flags"),
    [
        ({"GOOGLE_APPLICATION_CREDENTIALS": "/secret/path/key.json"}, ()),
        ({}, ("--env", "KEY=projects/p/locations/l/keyRings/r/cryptoKeys/k")),
    ],
)
def test_up_refuses_to_run_next_to_production_configuration(
    cli: Cli,
    short_dir: Path,
    fake_runner: FakeContainerRunner,
    monkeypatch: pytest.MonkeyPatch,
    host_env: dict[str, str],
    flags: tuple[str, ...],
) -> None:
    for name, value in host_env.items():
        monkeypatch.setenv(name, value)
    state = short_dir / "state"

    code, out, err = cli("up", "--state-dir", str(state), "--image", IMAGE, "--audience", AUDIENCE,
                         "--issuer-port", "0", *flags)  # fmt: skip

    assert (code, out, err) == (2, "", "PRODUCTION_CREDENTIALS_PRESENT\n")
    assert [call[1] for call in fake_runner.calls] == ["image"]
    assert not (state / "sim-state.json").exists()
    assert not (state / "launcher" / "teeserver.sock").exists()
