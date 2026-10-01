"""Simulated Confidential Space launcher socket."""

from collections.abc import Callable, Sequence
from pathlib import Path

from teecustody_sim.config import SimLimits


class LauncherServer:
    def __init__(
        self,
        socket_path: Path,
        *,
        mint: Callable[[str, Sequence[str]], str],
        limits: SimLimits,
    ) -> None:
        raise NotImplementedError("T-08")

    def start(self) -> None:
        raise NotImplementedError("T-08")

    def stop(self) -> None:
        raise NotImplementedError("T-08")
