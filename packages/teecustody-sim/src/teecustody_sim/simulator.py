"""Simulator facade: issuer plus launcher socket, as a context manager."""

import time
from collections.abc import Callable, Mapping
from types import TracebackType

from teecustody_sim.config import SimulatorConfig
from teecustody_sim.keys import SimKeys


class Simulator:
    def __init__(
        self,
        config: SimulatorConfig,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        raise NotImplementedError("T-08")

    def __enter__(self) -> "Simulator":
        raise NotImplementedError("T-08")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        raise NotImplementedError("T-08")

    def start(self) -> None:
        raise NotImplementedError("T-08")

    def stop(self) -> None:
        raise NotImplementedError("T-08")

    @property
    def issuer_origin(self) -> str:
        raise NotImplementedError("T-08")

    @property
    def discovery_url(self) -> str:
        raise NotImplementedError("T-08")

    @property
    def keys(self) -> SimKeys:
        raise NotImplementedError("T-08")
