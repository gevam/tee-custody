"""T-01: the frozen `notes_gateway` public API (INC-2-API §6, API-TL TL-5) and its packaging."""

from __future__ import annotations

import ast
import dataclasses
import importlib.metadata
import importlib.util
import inspect
import os
import re
import subprocess
import sys
import time
import tomllib
import types
import typing
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import fastapi
import pytest
import uvicorn

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


def _spec_uvicorn_config(
    app: fastapi.FastAPI, *, limits: GatewayLimits = GatewayLimits(), host: str, port: int
) -> uvicorn.Config: ...


def test_server_module_exports_exactly_uvicorn_config() -> None:
    from notes_gateway import server

    assert server.__all__ == ["uvicorn_config"]
    public = sorted(
        name
        for name, value in vars(server).items()
        if not name.startswith("_") and not isinstance(value, types.ModuleType)
    )
    assert public == ["uvicorn_config"]


def test_uvicorn_config_signature_equals_api_section_6_transcription() -> None:
    from notes_gateway import server

    assert inspect.signature(server.uvicorn_config, eval_str=True) == inspect.signature(
        _spec_uvicorn_config, eval_str=True
    )


def test_server_module_is_not_re_exported_from_the_package() -> None:
    assert "server" not in notes_gateway.__all__
    assert not hasattr(notes_gateway, "uvicorn_config")


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
    ("per_source_max_in_flight", 8),
    ("body_read_timeout_s", 10.0),
    ("header_read_timeout_s", 10.0),
    ("max_connections", 512),
    ("max_header_bytes", 8192),
    ("max_header_count", 64),
    ("write_timeout_s", 30.0),
)


def test_gateway_limits_fields_and_defaults_equal_api_section_6() -> None:
    limits = GatewayLimits()
    actual = tuple((f.name, getattr(limits, f.name)) for f in dataclasses.fields(limits))
    assert actual == _SPEC_LIMITS
    for name, value in _SPEC_LIMITS:
        assert type(getattr(limits, name)) is type(value)


def test_gateway_limits_has_the_seventeen_fields_of_the_amended_section_6() -> None:
    assert len(dataclasses.fields(GatewayLimits)) == 17


def test_gateway_limits_is_frozen() -> None:
    limits = GatewayLimits()
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.max_page = 1  # type: ignore[misc]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class _SpecGatewayLimits:
    max_request_bytes: int = 65536
    max_bundles: int = 16
    max_page: int = 32
    per_source_rate: float = 20.0
    per_source_burst: int = 40
    global_rate: float = 500.0
    global_burst: int = 1000
    max_concurrency: int = 64
    max_sources_tracked: int = 10_000
    cors_origins: tuple[str, ...] = ()
    per_source_max_in_flight: int = 8
    body_read_timeout_s: float = 10.0
    header_read_timeout_s: float = 10.0
    max_connections: int = 512
    max_header_bytes: int = 8192
    max_header_count: int = 64
    write_timeout_s: float = 30.0


def test_gateway_limits_signature_equals_spec_dataclass() -> None:
    assert inspect.signature(GatewayLimits, eval_str=True) == inspect.signature(
        _SpecGatewayLimits, eval_str=True
    )


def test_gateway_limits_annotation_types_equal_spec_dataclass() -> None:
    assert typing.get_type_hints(GatewayLimits) == typing.get_type_hints(_SpecGatewayLimits)


def test_gateway_limits_uses_slots_and_has_no_instance_dict() -> None:
    assert "__slots__" in vars(GatewayLimits)
    assert not hasattr(GatewayLimits(), "__dict__")


def test_gateway_limits_rejects_positional_arguments() -> None:
    with pytest.raises(TypeError):
        GatewayLimits(1)  # type: ignore[misc]


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


_GATEWAY_SOURCES = ("app.py", "dev.py")
_LAZY_SIMULATOR_IMPORT = "def main() -> None:\n    from teecustody_sim import Simulator\n"


@pytest.mark.parametrize("module_file", _GATEWAY_SOURCES)
def test_ruff_bans_cbor2_everywhere_in_gateway_source(module_file: str) -> None:
    result = _ruff_check(_importing("cbor2"), f"{_GATEWAY}/src/notes_gateway/{module_file}")
    assert result.returncode != 0
    assert "TID251" in result.stdout


@pytest.mark.parametrize("module_file", _GATEWAY_SOURCES)
def test_ruff_bans_module_level_simulator_import_in_gateway_source(module_file: str) -> None:
    result = _ruff_check(
        _importing("teecustody_sim"), f"{_GATEWAY}/src/notes_gateway/{module_file}"
    )
    assert result.returncode != 0
    assert "TID253" in result.stdout


def test_ruff_raises_no_import_ban_on_lazy_simulator_import_in_dev_module() -> None:
    result = _ruff_check(_LAZY_SIMULATOR_IMPORT, f"{_GATEWAY}/src/notes_gateway/dev.py")
    assert "TID251" not in result.stdout
    assert "TID253" not in result.stdout


def test_ruff_allows_used_lazy_simulator_import_in_dev_module() -> None:
    source = _LAZY_SIMULATOR_IMPORT + "    Simulator()\n"
    result = _ruff_check(source, f"{_GATEWAY}/src/notes_gateway/dev.py")
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize("module", ["teecustody_sim", "cbor2"])
def test_ruff_allows_banned_imports_in_gateway_tests(module: str) -> None:
    result = _ruff_check(_importing(module), f"{_GATEWAY}/tests/test_probe.py")
    assert result.returncode == 0, result.stdout


def test_ruff_toml_exempts_only_tests_from_import_bans() -> None:
    config = tomllib.loads((_REPO_ROOT / _GATEWAY / "ruff.toml").read_text(encoding="utf-8"))
    lint = config["lint"]
    assert "per-file-ignores" not in lint
    assert lint["extend-per-file-ignores"] == {"tests/**": ["TID251", "TID253"]}


def test_pytest_puts_repo_root_on_path_so_tests_support_imports() -> None:
    root = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert root["tool"]["pytest"]["ini_options"]["pythonpath"] == ["."]
    assert importlib.util.find_spec("tests.support") is not None
    assert importlib.util.find_spec("tests.support.channel_doubles") is not None


def test_dev_group_pins_httpx2_for_test_client_and_not_httpx() -> None:
    root = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev = root["dependency-groups"]["dev"]
    assert "httpx2==2.13.1" in dev
    assert not any(re.match(r"httpx(?![0-9])", req) for req in dev)


def test_test_client_imports_without_deprecation_warning() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", "from starlette.testclient import TestClient"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


# ------------------------------------------------- T-40 criterion 19 (A4.2, A4.3): internals
_GATEWAY_SRC = Path(notes_gateway.__file__).resolve().parent


def _imports_from(module_file: str) -> list[tuple[str, str]]:
    tree = ast.parse((_GATEWAY_SRC / module_file).read_text(encoding="utf-8"))
    return [
        (node.module or "", alias.name)
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    ]


def test_server_imports_only_h11protocol_from_uvicorns_h11_module() -> None:
    names = [
        name
        for module, name in _imports_from("server.py")
        if module == "uvicorn.protocols.http.h11_impl"
    ]
    assert names == ["H11Protocol"]


@pytest.mark.parametrize("module_file", sorted(p.name for p in _GATEWAY_SRC.glob("*.py")))
def test_no_gateway_module_imports_a_private_name_from_another_module(module_file: str) -> None:
    private = [(m, n) for m, n in _imports_from(module_file) if n.startswith("_")]
    assert private == []


def test_validate_limits_is_package_internal_in_app() -> None:
    from notes_gateway import app

    assert callable(app.validate_limits)
    assert not hasattr(app, "_validate")
    assert "validate_limits" not in notes_gateway.__all__
    assert not hasattr(notes_gateway, "validate_limits")
    doc = " ".join((app.validate_limits.__doc__ or "").split())
    assert "package-internal; used by `create_app` and `server.uvicorn_config`" in doc
