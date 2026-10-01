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


def _copy_fixture(source: Path, root: Path) -> None:
    """Copy a fixture tree; ``*.txt`` names keep recorded lock files out of prettier's reach."""
    shutil.copytree(source, root, dirs_exist_ok=True)
    for recorded in root.rglob("*.txt"):
        recorded.replace(recorded.with_suffix(""))


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _copy_fixture(FIXTURES / "clean", root)
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
    _copy_fixture(FIXTURES / "violations" / case, root)


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


def test_real_repository_passes_offline(tool: ModuleType) -> None:
    assert tool.main(["--offline"]) == 0


def _framework_forbidden_items() -> list[str]:
    items: list[str] = []
    in_block = False
    for line in (REPO / "framework.yaml").read_text().splitlines():
        if line.strip() == "forbidden_dependencies:":
            in_block = True
            continue
        if in_block:
            stripped = line.strip()
            if not stripped.startswith("- "):
                break
            items.append(stripped[2:].split("#", 1)[0].strip().strip('"'))
    return items


def test_every_framework_forbidden_dependency_is_enforced(tool: ModuleType) -> None:
    items = _framework_forbidden_items()
    assert len(items) >= 9
    for item in items:
        if item.startswith("any package that implements"):
            assert tool.KNOWN_CRYPTO, item
            continue
        name = item.split(" ", 1)[0]
        if " " in item:
            assert name in tool.FORBIDDEN_CONDITIONAL, item
        else:
            assert name in tool.FORBIDDEN, item


def _write(root: Path, relative: str, text: str) -> None:
    (root / relative).parent.mkdir(parents=True, exist_ok=True)
    (root / relative).write_text(text)


def _violations(
    tool: ModuleType, root: Path, capsys: pytest.CaptureFixture[str], *, offline: bool = True
) -> list[str]:
    argv = ["--root", str(root), "--today", TODAY] + (["--offline"] if offline else [])
    status = tool.main(argv, fetch_json=recorded_fetch)
    lines = capsys.readouterr().out.splitlines()
    assert status == (1 if lines else 0)
    return lines


CORE_MANIFEST = "packages/teecustody-core/package.json"


def test_npm_range_on_approved_crypto_is_unpinned(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = (clean_tree / CORE_MANIFEST).read_text().replace('"1.9.0"', '"^1.9.0"')
    _write(clean_tree, CORE_MANIFEST, text)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unpinned @hpke/core"]


def test_npm_lock_entry_without_integrity_is_unpinned(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    start = lock.index("  '@hpke/core@1.9.0':\n    resolution:")
    end = lock.index("\n", lock.index("resolution:", start))
    lock = lock[:start] + "  '@hpke/core@1.9.0':\n    resolution: {tarball: x}" + lock[end:]
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unpinned @hpke/core"]


def test_approved_crypto_absent_from_lock_is_unpinned(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (clean_tree / "pnpm-lock.yaml").unlink()
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unpinned @hpke/core"]


def test_noble_scope_is_unapproved_crypto(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    lock = lock.replace("packages:\n\n", "packages:\n\n  '@noble/curves@2.0.0':\n    x: 1\n\n", 1)
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unapproved @noble/curves"]


def test_simulator_in_any_client_manifest_is_rejected(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        clean_tree,
        "packages/teecustody-web/package.json",
        '{"name": "@teecustody/web", "devDependencies": {"teecustody-sim": "0.1.0"}}',
    )
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION sim-in-library teecustody-sim"]


def test_simulator_reached_transitively_from_the_library_is_rejected(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "uv.lock").read_text()
    lock = lock.replace(
        'name = "cbor2"\nversion = "6.1.4"\n',
        'name = "cbor2"\nversion = "6.1.4"\n'
        'dependencies = [\n    { name = "teecustody-sim" },\n]\n',
        1,
    )
    _write(clean_tree, "uv.lock", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION sim-in-library teecustody-sim"]


def test_core_peer_dependencies_count_as_runtime(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((clean_tree / CORE_MANIFEST).read_text())
    manifest["peerDependencies"] = {"zod": "3.0.0"}
    _write(clean_tree, CORE_MANIFEST, json.dumps(manifest))
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION core-runtime-deps zod"]


def test_stale_dev_dependency_is_exempt_but_licence_still_applies(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root_manifest = (clean_tree / "pyproject.toml").read_text()
    root_manifest = root_manifest.replace('"pytest==9.1.1"', '"pytest==9.1.1", "oldpkg==0.1.0"')
    root_manifest = root_manifest.replace('dev = ["', 'lint = ["gplpkg==1.0.0"]\ndev = ["')
    _write(clean_tree, "pyproject.toml", root_manifest)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION licence gplpkg"]


def test_build_backend_is_subject_to_the_age_rule(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "packages/teecustody-py/pyproject.toml"
    text = (clean_tree / path).read_text().replace("hatchling==1.32.4", "oldpkg==0.1.0")
    _write(clean_tree, path, text)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION stale oldpkg"]


def test_registry_failure_fails_closed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken(url: str) -> object:
        if "cbor2" in url:
            raise OSError("network down")
        return recorded_fetch(url)

    argv = ["--root", str(clean_tree), "--today", TODAY]
    assert tool.main(argv, fetch_json=broken) == 1
    captured = capsys.readouterr()
    assert captured.out == "VIOLATION licence cbor2\nVIOLATION stale cbor2\n"
    assert "cbor2" in captured.err


@pytest.mark.parametrize(
    ("expression", "allowed"),
    [
        ("MIT", True),
        ("Apache-2.0 OR BSD-3-Clause", True),
        ("GPL-3.0-only OR MIT", True),
        ("MIT AND GPL-3.0-only", False),
        ("MIT AND (GPL-3.0-only OR ISC)", True),
        ("(MIT OR GPL-3.0-only) AND GPL-2.0-only", False),
        ("Apache-2.0 WITH LLVM-exception", False),
        ("(MIT", False),
        ("(MIT ISC", False),
        ("MIT)", False),
        ("", False),
        ("SEE LICENSE IN LICENSE.txt", False),
    ],
)
def test_licence_expressions(tool: ModuleType, expression: str, allowed: bool) -> None:
    assert tool.licence_allowed(expression) is allowed


def test_pypi_licence_falls_back_to_classifiers(tool: ModuleType) -> None:
    info = {
        "license_expression": None,
        "license": "Copyright (c) Someone. Permission is hereby granted...",
        "classifiers": ["License :: OSI Approved :: BSD License", "Programming Language :: Python"],
    }
    assert tool.licence_allowed(tool._pypi_licence(info))
    assert not tool.licence_allowed(tool._pypi_licence({"classifiers": []}))


def test_npm_document_without_latest_release_is_stale_and_unlicensed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def empty_npm(url: str) -> object:
        return {} if "registry.npmjs.org" in url else recorded_fetch(url)

    argv = ["--root", str(clean_tree), "--today", TODAY]
    assert tool.main(argv, fetch_json=empty_npm) == 1
    assert capsys.readouterr().out.splitlines() == [
        "VIOLATION licence @hpke/core",
        "VIOLATION licence typescript",
        "VIOLATION stale @hpke/core",
    ]


def test_network_access_is_limited_to_the_two_registries(tool: ModuleType) -> None:
    with pytest.raises(ValueError, match="refusing"):
        tool.fetch_registry_json("file:///etc/passwd")
    with pytest.raises(ValueError, match="refusing"):
        tool.fetch_registry_json("https://pypi.org.evil.test/x")


def test_optional_and_grouped_manifest_entries_are_read(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = "packages/teecustody-sim/pyproject.toml"
    text = (clean_tree / path).read_text()
    text += '\n[project.optional-dependencies]\nfast = ["cbor2~=6.1"]\n'
    text += '\n[dependency-groups]\nall = [{ include-group = "fast" }]\n'
    _write(clean_tree, path, text)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unpinned cbor2"]


def test_non_object_registry_document_fails_closed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def listing(url: str) -> object:
        return [] if "typescript" in url else recorded_fetch(url)

    argv = ["--root", str(clean_tree), "--today", TODAY]
    assert tool.main(argv, fetch_json=listing) == 1
    assert capsys.readouterr().out == "VIOLATION licence typescript\n"
