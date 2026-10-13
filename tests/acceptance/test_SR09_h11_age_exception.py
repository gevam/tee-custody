"""SR-9 / D-049 / DEBT-3: the h11 age exception is exact (INC-2; owning task T-37).

The age rule exempts h11 0.16.0 only where it is reached as uvicorn's dependency inside the
notes-gateway member. Fixtures are built here from the clean tooling tree plus a gateway member; the
tool is driven through its CLI entry (`main`) with a recorded registry and `--today 2026-10-25`.

Expected failure on trunk: `VIOLATION stale h11` is reported (the exception does not exist yet).
"""

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
CLEAN = REPO / "tests" / "tooling" / "fixtures" / "clean"
RECORDED = REPO / "tests" / "tooling" / "fixtures" / "registry" / "pypi"
NPM = REPO / "tests" / "tooling" / "fixtures" / "registry" / "npm"
TODAY = "2026-10-25"
H11_RELEASED = "2025-04-24T00:00:00.000000Z"
RECENT = "2026-09-20T00:00:00.000000Z"

Registry = dict[str, dict[str, object]]


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dependency_policy_acc", REPO / "tools" / "dependency_policy.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["dependency_policy_acc"] = module
    spec.loader.exec_module(module)
    return module


def _doc(licence: str, released: str, version: str) -> dict[str, object]:
    return {
        "info": {
            "license_expression": licence,
            "license": None,
            "classifiers": [],
            "version": version,
        },
        "urls": [{"upload_time_iso_8601": released}],
    }


def _registry(h11_licence: str = "MIT") -> Registry:
    docs = {p.stem: json.loads(p.read_text()) for p in RECORDED.glob("*.json")}
    docs["h11"] = _doc(h11_licence, H11_RELEASED, "0.16.0")
    docs["uvicorn"] = _doc("BSD-3-Clause", RECENT, "0.54.0")
    return docs


LOCK_HEAD = """version = 1
revision = 3
requires-python = ">=3.12"

[manifest]
members = [
    "notes-gateway",
    "tee-custody-workspace",
    "teecustody",
    "teecustody-sim",
]
"""


def _package(name: str, version: str, extra: str = "") -> str:
    url = f"https://files.pythonhosted.org/packages/{name}-{version}.tar.gz"
    return (
        f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        f'source = {{ registry = "https://pypi.org/simple" }}\n'
        f'sdist = {{ url = "{url}", hash = "sha256:{"a" * 64}", size = 1 }}\n{extra}'
    )


def _build(
    root: Path,
    *,
    h11_version: str = "0.16.0",
    library_uses_h11: bool = False,
    gateway_direct_h11: bool = False,
    extra_stale: bool = False,
) -> None:
    shutil.copytree(CLEAN, root, dirs_exist_ok=True)
    for recorded in root.rglob("*.txt"):
        recorded.replace(recorded.with_suffix(""))
    gateway = root / "examples" / "notes-app" / "gateway"
    gateway.mkdir(parents=True)
    deps = ["teecustody==0.1.0", "uvicorn==0.54.0"]
    lock_deps = ['{ name = "teecustody" }', '{ name = "uvicorn" }']
    if gateway_direct_h11:
        deps.append(f"h11=={h11_version}")
        lock_deps.append('{ name = "h11" }')
    if extra_stale:
        deps.append("oldpkg==0.1.0")
        lock_deps.append('{ name = "oldpkg" }')
    (gateway / "pyproject.toml").write_text(
        '[project]\nname = "notes-gateway"\nversion = "0.1.0"\nrequires-python = ">=3.12"\n'
        f"dependencies = {json.dumps(deps)}\n"
    )
    if library_uses_h11:
        lib = root / "packages" / "teecustody-py" / "pyproject.toml"
        lib.write_text(
            lib.read_text().replace('"cbor2==6.1.4"', f'"cbor2==6.1.4", "h11=={h11_version}"')
        )
    lock = LOCK_HEAD
    lock += _package("cbor2", "6.1.4")
    lock += _package("cryptography", "50.0.2")
    lock += _package("h11", h11_version)
    if extra_stale:
        lock += _package("oldpkg", "0.1.0")
    lock += _package("pytest", "9.1.1")
    lock += _package("uvicorn", "0.54.0", 'dependencies = [\n    { name = "h11" },\n]\n')
    lock += (
        '\n[[package]]\nname = "notes-gateway"\nversion = "0.1.0"\n'
        'source = { editable = "examples/notes-app/gateway" }\n'
        "dependencies = [\n    " + ",\n    ".join(lock_deps) + ",\n]\n"
    )
    lock += (
        '\n[[package]]\nname = "tee-custody-workspace"\nversion = "0.0.0"\n'
        'source = { virtual = "." }\ndependencies = [\n    { name = "teecustody" },\n'
        '    { name = "teecustody-sim" },\n]\n\n[package.dev-dependencies]\n'
        'dev = [\n    { name = "pytest" },\n]\n'
    )
    h11_dep = '    { name = "h11" },\n' if library_uses_h11 else ""
    lock += (
        '\n[[package]]\nname = "teecustody"\nversion = "0.1.0"\n'
        'source = { editable = "packages/teecustody-py" }\ndependencies = [\n'
        '    { name = "cbor2" },\n    { name = "cryptography" },\n' + h11_dep + "]\n"
    )
    lock += (
        '\n[[package]]\nname = "teecustody-sim"\nversion = "0.1.0"\n'
        'source = { editable = "packages/teecustody-sim" }\ndependencies = [\n'
        '    { name = "cryptography" },\n    { name = "teecustody" },\n]\n'
    )
    (root / "uv.lock").write_text(lock)


def _run(
    root: Path, registry: Registry, capsys: pytest.CaptureFixture[str]
) -> tuple[int, list[str]]:
    def fetch(url: str) -> object:
        if url.startswith("https://registry.npmjs.org/"):
            name, _, version = url[len("https://registry.npmjs.org/") :].partition("/")
            name = name.replace("%2F", "/").replace("%2f", "/")
            document = json.loads((NPM / f"{name.replace('/', '__')}.json").read_text())
            return document["versions"].get(version, {}) if version else document
        name = url.split("/pypi/", 1)[1].split("/", 1)[0]
        return registry[name]

    code = _tool().main(["--root", str(root), "--today", TODAY], fetch_json=fetch)
    return code, capsys.readouterr().out.splitlines()


def _positive_control(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The exception must exist for the narrowing tests below to mean anything."""
    control = tmp_path / "control"
    _build(control)
    _code, lines = _run(control, _registry(), capsys)
    assert "VIOLATION stale h11" not in lines


def test_SR09_h11_0_16_0_reached_only_through_uvicorn_in_the_gateway_is_not_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given notes-gateway -> uvicorn -> h11 0.16.0 (released 2025-04-24) and today = 2026-10-25
    _build(tmp_path)
    # When the dependency policy runs online against the recording
    code, lines = _run(tmp_path, _registry(), capsys)
    # Then h11 is not reported stale, and the tree passes
    assert "VIOLATION stale h11" not in lines
    assert (code, lines) == (0, [])


def test_SR09_any_other_h11_version_is_still_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _positive_control(tmp_path, capsys)
    _build(tmp_path / "case", h11_version="0.15.0")
    _code, lines = _run(tmp_path / "case", _registry(), capsys)
    assert "VIOLATION stale h11" in lines


def test_SR09_h11_in_the_library_closure_is_still_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _positive_control(tmp_path, capsys)
    _build(tmp_path / "case", library_uses_h11=True)
    _code, lines = _run(tmp_path / "case", _registry(), capsys)
    assert "VIOLATION stale h11" in lines


def test_SR09_h11_as_a_direct_gateway_dependency_is_still_stale(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _positive_control(tmp_path, capsys)
    _build(tmp_path / "case", gateway_direct_h11=True)
    _code, lines = _run(tmp_path / "case", _registry(), capsys)
    assert "VIOLATION stale h11" in lines


def test_SR09_other_stale_gateway_packages_are_still_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _build(tmp_path, extra_stale=True)
    registry = _registry()
    registry["oldpkg"] = json.loads((RECORDED / "oldpkg.json").read_text())
    code, lines = _run(tmp_path, registry, capsys)
    assert code == 1
    assert lines == ["VIOLATION stale oldpkg"]


def test_SR09_the_exception_covers_age_only_not_the_licence(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _build(tmp_path)
    _code, lines = _run(tmp_path, _registry(h11_licence="GPL-3.0-only"), capsys)
    assert lines == ["VIOLATION licence h11"]
