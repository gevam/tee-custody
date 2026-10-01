"""Container runtime wrapper (docker or podman).

Every subprocess call takes an argv list and never a shell; that is the reason for each `nosec`
marker below (argv list, no shell).
"""

import re
import subprocess  # nosec B404
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final, Literal

from teecustody_sim.constants import CONTAINER_LAUNCHER_DIR

_IMAGE_ID: Final = re.compile(r"sha256:[0-9a-f]{64}\n?")
# Docker/OCI reference grammar (distribution/reference): [domain/]path[:tag][@digest]. A reference
# can never start with "-", so it is never read as a runtime option.
_DOMAIN_COMPONENT: Final = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
_PATH_COMPONENT: Final = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_IMAGE_REFERENCE: Final = re.compile(
    rf"(?P<name>(?:{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]+)?/)?"
    rf"{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?",
    re.ASCII,
)
_MAX_NAME_LENGTH: Final = 255
_ENV_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
_INVALID_PATH: Final = "INVALID_PATH"
_INVALID_LAUNCH_CONFIG: Final = "INVALID_LAUNCH_CONFIG"
_EXECUTABLES: Final = frozenset({"docker", "podman"})


def _check_image_reference(image: str) -> None:
    match = _IMAGE_REFERENCE.fullmatch(image)
    if match is None or len(match["name"]) > _MAX_NAME_LENGTH:
        raise ValueError(_INVALID_LAUNCH_CONFIG)


def _is_argv_text(value: str) -> bool:
    """An argv element must be UTF-8 text without NUL (which the OS cannot pass)."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return "\0" not in value


def _check_launcher_dir(launcher_dir: Path) -> None:
    text = str(launcher_dir)
    if not launcher_dir.is_absolute() or ":" in text or not _is_argv_text(text):
        raise ValueError(_INVALID_PATH)


def _check_launch(args: Sequence[str], env: Sequence[tuple[str, str]]) -> None:
    if not all(_is_argv_text(arg) for arg in args) or not all(
        _ENV_NAME.fullmatch(name) and _is_argv_text(value) for name, value in env
    ):
        raise ValueError(_INVALID_LAUNCH_CONFIG)


def _check_run_arguments(
    image: str, launcher_dir: Path, args: Sequence[str], env: Sequence[tuple[str, str]]
) -> None:
    """Everything `run_workload` checks; the CLI also calls it before any state is written."""
    _check_image_reference(image)
    _check_launcher_dir(launcher_dir)
    _check_launch(args, env)


def _run_attached(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """The workload's own output stays on this terminal."""
    return subprocess.run(argv, capture_output=False, text=True, check=False)  # noqa: S603  # nosec B603


def _run_captured(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """`image inspect` output is parsed, and the runtime's own error text never reaches stderr."""
    return subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603  # nosec B603


class ContainerRuntime:
    def __init__(
        self,
        executable: Literal["docker", "podman"],
        *,
        run: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        if executable not in _EXECUTABLES:
            raise ValueError(_INVALID_LAUNCH_CONFIG)
        self._executable = executable
        self._run_workload = run or _run_attached
        self._run_inspect = run or _run_captured

    def image_digest(self, image: str) -> str:
        _check_image_reference(image)
        result = self._run_inspect(
            [self._executable, "image", "inspect", "--format", "{{.Id}}", image]
        )
        output = result.stdout
        if result.returncode != 0 or output is None or _IMAGE_ID.fullmatch(output) is None:
            raise ValueError(_INVALID_LAUNCH_CONFIG)
        return output.rstrip("\n")

    def run_workload(
        self,
        image: str,
        *,
        launcher_dir: Path,
        args: Sequence[str],
        env: Sequence[tuple[str, str]],
    ) -> int:
        _check_run_arguments(image, launcher_dir, args, env)
        env_options = [option for name, value in env for option in ("-e", f"{name}={value}")]
        argv = [
            self._executable,
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{launcher_dir}:{CONTAINER_LAUNCHER_DIR}",
            *env_options,
            image,
            *args,
        ]
        return self._run_workload(argv).returncode
