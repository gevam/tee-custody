"""T-14: tools/dependency_policy.py enforces framework.yaml dependency_policy (SR-9, NFR-6, D-019)."""

import importlib.util
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
