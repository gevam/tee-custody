"""T-16: the container runtime wrapper (spec §15.2 item 1; API.md §C `runtime.py`)."""

import subprocess
from collections.abc import Sequence
from pathlib import Path

import pytest

from teecustody_sim import ContainerRuntime

IMAGE = "localhost/teecustody-t16:1"
DIGEST = "sha256:" + "0123456789abcdef" * 4


class FakeRunner:
    """Records every argv and answers with a fixed exit code and stdout."""

    def __init__(self, *, returncode: int = 0, stdout: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self._returncode = returncode
        self._stdout = stdout

    def __call__(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), self._returncode, self._stdout, None)


@pytest.mark.parametrize("executable", ["docker", "podman"])
def test_image_digest_inspects_the_image_and_returns_its_id(executable: str) -> None:
    runner = FakeRunner(stdout=DIGEST + "\n")
    runtime = ContainerRuntime(executable, run=runner)

    assert runtime.image_digest(IMAGE) == DIGEST
    assert runner.calls == [[executable, "image", "inspect", "--format", "{{.Id}}", IMAGE]]


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (0, "sha256:" + "0123456789ABCDEF" * 4 + "\n"),
        (0, "sha256:" + "ab" * 31 + "\n"),
        (0, "sha512:" + "ab" * 32 + "\n"),
        (0, DIGEST + "\n" + DIGEST + "\n"),
        (0, " " + DIGEST + "\n"),
        (0, DIGEST + "\n\n"),
        (0, ""),
        (0, None),
        (1, DIGEST + "\n"),
    ],
)
def test_image_digest_rejects_anything_but_one_sha256_id(
    returncode: int, stdout: str | None
) -> None:
    runtime = ContainerRuntime("docker", run=FakeRunner(returncode=returncode, stdout=stdout))

    with pytest.raises(ValueError, match=r"^INVALID_LAUNCH_CONFIG$"):
        runtime.image_digest(IMAGE)


@pytest.mark.parametrize(
    "image",
    [
        "busybox",
        "localhost/teecustody-t16:1",
        "ghcr.io/org/team/app:v1.2_rc-3",
        "registry.local:5000/a__b/c-d.e@" + DIGEST,
        "registry-1.example/app:latest@" + DIGEST,
    ],
)
def test_image_digest_accepts_docker_references(image: str) -> None:
    runner = FakeRunner(stdout=DIGEST + "\n")

    assert ContainerRuntime("podman", run=runner).image_digest(image) == DIGEST
    assert runner.calls[0][-1] == image


BAD_IMAGES = [
    "",
    "-v",
    "--privileged",
    "localhost/Upper",
    "app name",
    "app;id",
    "app\n",
    "app:",
    ":tag",
    "app@sha256:" + "ab" * 31,
    "app:" + "t" * 129,
    "a/" * 200 + "b",
    "app\udcff",
    "/abs/path",
    "app//b",
]


@pytest.mark.parametrize("image", BAD_IMAGES)
def test_image_digest_rejects_bad_references_before_running_anything(image: str) -> None:
    runner = FakeRunner(stdout=DIGEST + "\n")

    with pytest.raises(ValueError, match=r"^INVALID_LAUNCH_CONFIG$"):
        ContainerRuntime("docker", run=runner).image_digest(image)
    assert runner.calls == []


def test_run_workload_runs_the_image_isolated_with_only_the_given_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOST_ONLY_SECRET", "host-value")
    runner = FakeRunner(returncode=7)
    runtime = ContainerRuntime("podman", run=runner)

    code = runtime.run_workload(
        IMAGE,
        launcher_dir=Path("/srv/state/launcher"),
        args=["/app/workload", "--flag", "two words"],
        env=[("MODE", "test"), ("EMPTY", ""), ("WITH_EQUALS", "a=b")],
    )

    assert code == 7
    assert runner.calls == [
        [
            "podman", "run", "--rm", "--network", "none",
            "-v", "/srv/state/launcher:/run/container_launcher",
            "-e", "MODE=test", "-e", "EMPTY=", "-e", "WITH_EQUALS=a=b",
            IMAGE, "/app/workload", "--flag", "two words",
        ]
    ]  # fmt: skip
    assert not any("HOST_ONLY_SECRET" in part or "host-value" in part for part in runner.calls[0])


def _run_workload(
    runner: FakeRunner,
    *,
    image: str = IMAGE,
    launcher_dir: Path = Path("/srv/state/launcher"),
    args: Sequence[str] = ("/app/workload",),
    env: Sequence[tuple[str, str]] = (("MODE", "test"),),
) -> int:
    runtime = ContainerRuntime("docker", run=runner)
    return runtime.run_workload(image, launcher_dir=launcher_dir, args=args, env=env)


@pytest.mark.parametrize("image", BAD_IMAGES)
def test_run_workload_rejects_bad_references_before_running_anything(image: str) -> None:
    runner = FakeRunner()

    with pytest.raises(ValueError, match=r"^INVALID_LAUNCH_CONFIG$"):
        _run_workload(runner, image=image)
    assert runner.calls == []


@pytest.mark.parametrize(
    "launcher_dir",
    [Path("relative/launcher"), Path("/srv/a:/etc"), Path("/srv/a:ro"), Path("/srv/\udcff")],
)
def test_run_workload_rejects_a_mount_source_that_is_not_one_absolute_path(
    launcher_dir: Path,
) -> None:
    runner = FakeRunner()

    with pytest.raises(ValueError, match=r"^INVALID_PATH$"):
        _run_workload(runner, launcher_dir=launcher_dir)
    assert runner.calls == []


@pytest.mark.parametrize(
    ("args", "env"),
    [
        ((), (("", "x"),)),
        ((), (("A=B", "x"),)),
        ((), (("1ABC", "x"),)),
        ((), (("A B", "x"),)),
        ((), (("A\n", "x"),)),
        ((), (("A", "nul\0"),)),
        ((), (("A", "\udcff"),)),
        (("nul\0",), ()),
        (("\ud800",), ()),
    ],
)
def test_run_workload_rejects_unsafe_args_and_env_before_running_anything(
    args: Sequence[str], env: Sequence[tuple[str, str]]
) -> None:
    runner = FakeRunner()

    with pytest.raises(ValueError, match=r"^INVALID_LAUNCH_CONFIG$"):
        _run_workload(runner, args=args, env=env)
    assert runner.calls == []


class RecordingSubprocessRun:
    """Stands in for `subprocess.run` to observe the default runner's arguments."""

    def __init__(self, *, stdout: str | None, returncode: int) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self._stdout = stdout
        self._returncode = returncode

    def __call__(self, argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(list(argv), self._returncode, self._stdout, None)


def test_default_runner_runs_the_workload_attached_with_an_argv_list_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = RecordingSubprocessRun(stdout=None, returncode=3)
    monkeypatch.setattr(subprocess, "run", recorder)

    code = ContainerRuntime("docker").run_workload(
        IMAGE, launcher_dir=Path("/srv/l"), args=(), env=()
    )

    assert code == 3
    [(argv, kwargs)] = recorder.calls
    assert argv[:2] == ["docker", "run"]
    assert kwargs == {"capture_output": False, "text": True, "check": False}


def test_default_runner_captures_the_inspect_output_with_an_argv_list_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = RecordingSubprocessRun(stdout=DIGEST + "\n", returncode=0)
    monkeypatch.setattr(subprocess, "run", recorder)

    assert ContainerRuntime("podman").image_digest(IMAGE) == DIGEST
    [(argv, kwargs)] = recorder.calls
    assert argv == ["podman", "image", "inspect", "--format", "{{.Id}}", IMAGE]
    assert kwargs == {"capture_output": True, "text": True, "check": False}


@pytest.mark.parametrize("executable", ["", "sh", "/usr/bin/docker", "docker --help", "Docker"])
def test_only_docker_or_podman_can_be_the_runtime(executable: str) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_LAUNCH_CONFIG$"):
        ContainerRuntime(executable, run=FakeRunner())
