"""Container runtime wrapper (docker or podman)."""

import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Literal


class ContainerRuntime:
    def __init__(
        self,
        executable: Literal["docker", "podman"],
        *,
        run: Callable[[Sequence[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        raise NotImplementedError

    def image_digest(self, image: str) -> str:
        raise NotImplementedError

    def run_workload(
        self,
        image: str,
        *,
        launcher_dir: Path,
        args: Sequence[str],
        env: Sequence[tuple[str, str]],
    ) -> int:
        raise NotImplementedError
