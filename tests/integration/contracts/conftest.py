"""Fixtures for the INC-1 contract tests (Tech Lead, Wave 0).

`tc_contract_support` holds shared helpers; this directory is put on `sys.path` so test modules can
import it under `--import-mode=importlib`.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from tc_contract_support import RunningSimulator, simulator_config

from teecustody_sim import Simulator


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A short directory: AF_UNIX socket paths are limited to about 100 bytes."""
    path = Path(tempfile.mkdtemp(prefix="tc", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def running_simulator(short_dir: Path) -> Iterator[RunningSimulator]:
    config = simulator_config(short_dir)
    with Simulator(config, environ={}) as simulator:
        yield RunningSimulator(simulator=simulator, config=config)
