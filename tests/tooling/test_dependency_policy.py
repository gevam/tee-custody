"""T-14: tools/dependency_policy.py enforces framework.yaml dependency_policy (SR-9, D-019)."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dependency_policy", REPO / "tools" / "dependency_policy.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dependency_policy"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    return _load_tool()


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "clean", root)
    return root


def test_clean_tree_offline_passes_silently(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert tool.main(["--root", str(clean_tree), "--offline"]) == 0
    assert capsys.readouterr().out == ""


TODAY = "2026-10-01"
REGISTRY = FIXTURES / "registry"


def recorded_fetch(url: str) -> object:
    """Serve registry responses recorded under fixtures/registry; any other URL fails the test."""
    pypi_prefix, npm_prefix = "https://pypi.org/pypi/", "https://registry.npmjs.org/"
    if url.startswith(pypi_prefix) and url.endswith("/json"):
        path = REGISTRY / "pypi" / f"{url[len(pypi_prefix) : -len('/json')]}.json"
    elif url.startswith(npm_prefix):
        name = url[len(npm_prefix) :].replace("%2F", "/").replace("%2f", "/")
        path = REGISTRY / "npm" / f"{name.replace('/', '__')}.json"
    else:
        raise AssertionError(f"unexpected URL {url}")
    return json.loads(path.read_text())


def _apply_overlay(root: Path, case: str) -> None:
    shutil.copytree(FIXTURES / "violations" / case, root, dirs_exist_ok=True)


VIOLATION_CASES = [
    ("forbidden", "forbidden", "crypto-js", True),
    ("crypto-unapproved", "crypto-unapproved", "pynacl", True),
    ("crypto-unpinned-range", "crypto-unpinned", "cbor2", True),
    ("crypto-unpinned-hash", "crypto-unpinned", "cryptography", True),
    ("sim-in-library", "sim-in-library", "teecustody-sim", True),
    ("core-runtime-deps", "core-runtime-deps", "left-pad", True),
    ("cbor-x-unused", "cbor-x-unused", "cbor-x", True),
    ("licence", "licence", "gplpkg", False),
    ("stale", "stale", "oldpkg", False),
]


@pytest.mark.parametrize(("case", "rule", "package", "offline"), VIOLATION_CASES)
def test_each_rule_reports_exactly_its_violation(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    case: str,
    rule: str,
    package: str,
    offline: bool,
) -> None:
    _apply_overlay(clean_tree, case)
    argv = ["--root", str(clean_tree), "--today", TODAY] + (["--offline"] if offline else [])

    assert tool.main(argv, fetch_json=recorded_fetch) == 1
    assert capsys.readouterr().out == f"VIOLATION {rule} {package}\n"


def test_clean_tree_online_passes_with_recorded_registry(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--root", str(clean_tree), "--today", TODAY]
    assert tool.main(argv, fetch_json=recorded_fetch) == 0
    assert capsys.readouterr().out == ""
