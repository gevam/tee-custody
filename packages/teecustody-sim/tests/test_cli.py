"""T-16: the `teecustody-sim` command line (API.md §C CLI; PROJECT.md §4.2; spec §15)."""

import base64
import json
import logging
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


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    """Runs `main` and checks every invocation's stdout and stderr for key material (SR-7)."""

    def run(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        captured = capsys.readouterr()
        assert_no_key_material(captured.out, captured.err)
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
    assert_no_key_material(out_file.read_text())


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


IMAGE = "localhost/teecustody-t16-up:2"
IMAGE_ID = "sha256:" + "5a" * 32


class FakeContainerRunner:
    """Answers `image inspect`; on `run`, calls the launcher socket the way the workload would."""

    def __init__(self, *, inspect_stdout: str = IMAGE_ID + "\n", exit_code: int = 5) -> None:
        self.calls: list[list[str]] = []
        self.seen_inside: dict[str, Any] = {}
        self.inspect_stdout = inspect_stdout
        self._exit_code = exit_code

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
        return subprocess.CompletedProcess(list(argv), self._exit_code, None, None)


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
