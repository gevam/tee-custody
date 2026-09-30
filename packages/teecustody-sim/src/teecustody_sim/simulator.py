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
        raise NotImplementedError

    def __enter__(self) -> "Simulator":
        raise NotImplementedError

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        raise NotImplementedError

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    @property
    def issuer_origin(self) -> str:
        raise NotImplementedError

    @property
    def discovery_url(self) -> str:
        raise NotImplementedError

    @property
    def keys(self) -> SimKeys:
        raise NotImplementedError
