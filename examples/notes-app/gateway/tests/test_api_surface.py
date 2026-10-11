"""T-01: the frozen `notes_gateway` public API (INC-2-API §6, API-TL TL-5) and its packaging."""

from __future__ import annotations

import ast
import dataclasses
import importlib.metadata
import inspect
import os
import re
import subprocess
import sys
import time
import types
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import fastapi
import pytest

import notes_gateway
from notes_gateway import GatewayLimits, create_app

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue


def _spec_create_app(
    queue: RelayQueue,
    *,
    limits: GatewayLimits = GatewayLimits(),
    rng: Callable[[int], bytes] = os.urandom,
    clock: Callable[[], float] = time.monotonic,
) -> fastapi.FastAPI: ...


def test_package_exports_exactly_create_app_and_gateway_limits() -> None:
    assert sorted(notes_gateway.__all__) == ["GatewayLimits", "create_app"]
    public = sorted(
        name
        for name, value in vars(notes_gateway).items()
        if not name.startswith("_") and not isinstance(value, types.ModuleType)
    )
    assert public == ["GatewayLimits", "create_app"]


def test_create_app_signature_equals_api_transcription() -> None:
    assert inspect.signature(create_app) == inspect.signature(_spec_create_app)


def _spec_dev_main(argv: Sequence[str] | None = None) -> int: ...


def test_dev_main_signature_equals_api_tl_transcription() -> None:
    from notes_gateway import dev

    assert inspect.signature(dev.main, eval_str=True) == inspect.signature(
        _spec_dev_main, eval_str=True
    )


def test_dev_module_runs_main_as_its_exit_status() -> None:
    from notes_gateway import dev

    tree = ast.parse(Path(inspect.getfile(dev)).read_text(encoding="utf-8"))
    last = ast.unparse(tree.body[-1])
    assert last == "if __name__ == '__main__':\n    raise SystemExit(main())"


_SPEC_LIMITS: tuple[tuple[str, object], ...] = (
    ("max_request_bytes", 65536),
    ("max_bundles", 16),
    ("max_page", 32),
    ("per_source_rate", 20.0),
    ("per_source_burst", 40),
    ("global_rate", 500.0),
    ("global_burst", 1000),
    ("max_concurrency", 64),
    ("max_sources_tracked", 10_000),
    ("cors_origins", ()),
)


def test_gateway_limits_fields_and_defaults_equal_api_section_6() -> None:
    limits = GatewayLimits()
    actual = tuple((f.name, getattr(limits, f.name)) for f in dataclasses.fields(limits))
    assert actual == _SPEC_LIMITS
    for name, value in _SPEC_LIMITS:
        assert type(getattr(limits, name)) is type(value)


def test_gateway_limits_is_frozen() -> None:
    limits = GatewayLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_page = 1  # type: ignore[misc]


def test_distribution_requires_exactly_pinned_fastapi_teecustody_uvicorn() -> None:
    requires = sorted(importlib.metadata.requires("notes-gateway") or [])
    names = [re.split(r"[=<>!~ ;\[]", req, maxsplit=1)[0] for req in requires]
    assert names == ["fastapi", "teecustody", "uvicorn"]
    assert all(re.fullmatch(r"[a-z]+==\d+(\.\d+)*", req) for req in requires)
    assert "teecustody==0.1.0" in requires
    assert not any("teecustody-sim" in req or "teecustody_sim" in req for req in requires)


_REPO_ROOT = Path(__file__).resolve().parents[4]
_GATEWAY = "examples/notes-app/gateway"


def _ruff_check(source: str, stdin_filename: str) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "ruff", "check", "--no-cache"]
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [*argv, "--stdin-filename", stdin_filename, "-"],
        input=source,
        capture_output=True,
        text=True,
        cwd=_REPO_ROOT,
        check=False,
    )


def _importing(module: str) -> str:
    return f"import {module}\n\nPROBE = {module}\n"


@pytest.mark.parametrize("module", ["teecustody_sim", "cbor2"])
def test_ruff_bans_simulator_and_cbor_imports_in_gateway_source(module: str) -> None:
    result = _ruff_check(_importing(module), f"{_GATEWAY}/src/notes_gateway/app.py")
    assert result.returncode != 0
    assert "TID251" in result.stdout


def test_ruff_allows_simulator_import_in_dev_module() -> None:
    result = _ruff_check(_importing("teecustody_sim"), f"{_GATEWAY}/src/notes_gateway/dev.py")
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("module", ["teecustody_sim", "cbor2"])
def test_ruff_allows_banned_imports_in_gateway_tests(module: str) -> None:
    result = _ruff_check(_importing(module), f"{_GATEWAY}/tests/test_probe.py")
    assert result.returncode == 0, result.stdout
