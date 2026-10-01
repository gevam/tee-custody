"""Shared fixtures for INC-1 acceptance tests (QA). Synthetic values only; no cloud credentials."""

import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from acc_support import (
    AUDIENCE,
    IMAGE_DIGEST,
    IMAGE_REFERENCE,
    FakeClock,
    RunningSim,
)
from teecustody_sim import LaunchConfig, Simulator, SimulatorConfig


@pytest.fixture
def workdir() -> Iterator[Path]:
    # Short path: AF_UNIX socket paths are limited to ~108 bytes.
    path = Path(tempfile.mkdtemp(prefix="tca"))
    yield path
    shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def make_config(workdir: Path) -> Callable[..., SimulatorConfig]:
    def _make(**overrides: Any) -> SimulatorConfig:
        launch = LaunchConfig(
            image_reference=IMAGE_REFERENCE,
            image_digest=IMAGE_DIGEST,
            args=("/app/workload",),
            env=(("PYTHONUNBUFFERED", "1"),),
        )
        params: dict[str, Any] = {
            "state_dir": workdir / "state",
            "socket_path": workdir / "l.sock",
            "token_file_path": workdir / "token",
            "launch": launch,
            "audience": AUDIENCE,
            "issuer_port": 0,
        }
        params.update(overrides)
        return SimulatorConfig(**params)

    return _make


@pytest.fixture
def running_sim(make_config: Callable[..., SimulatorConfig]) -> Iterator[RunningSim]:
    config = make_config()
    clock = FakeClock()
    sim = Simulator(config, environ={}, clock=clock)
    sim.start()
    try:
        yield RunningSim(sim, config, clock)
    finally:
        try:
            sim.stop()
        except Exception:  # noqa: BLE001 - already stopped by the test
            pass
