"""T-14: tools/dependency_policy.py enforces framework.yaml dependency_policy (SR-9, D-019)."""

import importlib.util
import json
import re
import shutil
import sys
import tomllib
from collections.abc import Callable
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
    """Serve registry responses recorded under fixtures/registry; any other URL fails the test.

    Project documents are recorded; a version document is the recorded project document (PyPI, which
    has the same shape) or its ``versions[v]`` entry (npm).
    """
    pypi_prefix, npm_prefix = "https://pypi.org/pypi/", "https://registry.npmjs.org/"
    if url.startswith(pypi_prefix) and url.endswith("/json"):
        name = url[len(pypi_prefix) : -len("/json")].split("/", 1)[0]
        return json.loads((REGISTRY / "pypi" / f"{name}.json").read_text())
    if url.startswith(npm_prefix):
        name, _, version = url[len(npm_prefix) :].partition("/")
        name = name.replace("%2F", "/").replace("%2f", "/")
        document = json.loads((REGISTRY / "npm" / f"{name.replace('/', '__')}.json").read_text())
        return document["versions"].get(version, {}) if version else document
    raise AssertionError(f"unexpected URL {url}")


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
    ("hpke-common-direct", "hpke-common-direct", "packages/teecustody-web/package.json", True),
    ("crypto-unsigned-version", "crypto-unsigned-version", "@hpke/common", True),
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


# Pure-Python / pure-JS X25519, Ed25519, AES, HKDF or HPKE implementations (framework.yaml
# forbidden_dependencies, last item); none is on the approved list.
PURE_CRYPTO_IMPLEMENTATIONS = [
    "pyaes",
    "tinyec",
    "pure25519",
    "ed25519",
    "x25519",
    "hkdf",
    "tweetnacl",
    "js-nacl",
    "aes-js",
    "futoin-hkdf",
    "@noble/curves",
    "@noble/ciphers",
    "@stablelib/x25519",
    "@stablelib/ed25519",
    "@stablelib/hkdf",
    "@hpke/dhkem-x25519",
    "@hpke/chacha20poly1305",
]


def test_every_framework_forbidden_dependency_is_enforced(tool: ModuleType) -> None:
    items = _framework_forbidden_items()
    assert len(items) >= 9
    for item in items:
        if item.startswith("any package that implements"):
            for pure in PURE_CRYPTO_IMPLEMENTATIONS:
                assert tool.is_known_crypto(pure), pure
                assert pure not in tool.APPROVED_CRYPTO, pure
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


WEB_MANIFEST = "packages/teecustody-web/package.json"


def test_npm_range_on_approved_crypto_is_unpinned(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = (clean_tree / WEB_MANIFEST).read_text().replace('"1.9.0"', '"^1.9.0"')
    _write(clean_tree, WEB_MANIFEST, text)
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION crypto-unpinned @hpke/core",
        "VIOLATION crypto-unpinned-range @hpke/core",
    ]


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
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION lock-unparseable pnpm-lock.yaml",
        "VIOLATION crypto-unpinned @hpke/core",
    ]


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
    manifest = json.loads((clean_tree / "packages/teecustody-core/package.json").read_text())
    manifest["peerDependencies"] = {"zod": "3.0.0"}
    _write(clean_tree, "packages/teecustody-core/package.json", json.dumps(manifest))
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
        ("MIT-0", True),
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


def _reindent(text: str) -> str:
    return "\n".join(line.replace("  ", "    ") for line in text.splitlines()) + "\n"


def test_reindented_pnpm_lock_with_banned_packages_fails_closed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    extra = (
        "  node-forge@1.3.1:\n    resolution: {integrity: sha512-x}\n\n"
        "  '@noble/curves@2.0.0':\n    resolution: {integrity: sha512-x}\n\n"
    )
    lock = lock.replace("packages:\n\n", "packages:\n\n" + extra, 1)
    _write(clean_tree, "pnpm-lock.yaml", _reindent(lock))
    lines = _violations(tool, clean_tree, capsys)
    assert "VIOLATION lock-unparseable pnpm-lock.yaml" in lines


def test_pnpm_lock_line_outside_the_grammar_fails_closed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    lock = lock.replace("packages:\n\n", "packages:\n\n  stray line without a colon\n\n", 1)
    _write(clean_tree, "pnpm-lock.yaml", lock)
    # Nothing from an unparseable lock is trusted, so the approved crypto pin is unproven too.
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION lock-unparseable pnpm-lock.yaml",
        "VIOLATION crypto-unpinned @hpke/core",
    ]


def test_importer_dependency_missing_from_packages_is_inconsistent(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    start = lock.index("  typescript@5.9.3:\n    resolution")
    end = lock.index("\n\n", start) + 2
    lock = lock[:start] + lock[end:]
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION lock-inconsistent typescript"]


@pytest.mark.parametrize("text", ["version = 1\nrevision = 3\n", "[[package]\nname = "])
def test_uv_lock_without_packages_or_not_toml_fails_closed(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str], text: str
) -> None:
    _write(clean_tree, "uv.lock", text)
    assert "VIOLATION lock-unparseable uv.lock" in _violations(tool, clean_tree, capsys)


def test_forbidden_and_unapproved_names_in_manifests_are_rejected(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((clean_tree / "package.json").read_text())
    manifest["devDependencies"].update({"node-forge": "1.3.1", "@noble/curves": "2.0.0"})
    _write(clean_tree, "package.json", json.dumps(manifest))
    root = (clean_tree / "pyproject.toml").read_text()
    _write(
        clean_tree,
        "pyproject.toml",
        root.replace('"pytest==9.1.1"', '"pytest==9.1.1", "PyAES==1.6.1"'),
    )
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION forbidden node-forge",
        "VIOLATION forbidden pyaes",
        "VIOLATION crypto-unapproved @noble/curves",
    ]


@pytest.mark.parametrize("name", PURE_CRYPTO_IMPLEMENTATIONS)
def test_pure_crypto_implementation_in_lock_is_rejected(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    entry = f"  '{name}@1.0.0':\n    resolution: {{integrity: sha512-x}}\n\n"
    _write(clean_tree, "pnpm-lock.yaml", lock.replace("packages:\n\n", "packages:\n\n" + entry, 1))
    rule = "forbidden" if name in tool.FORBIDDEN else "crypto-unapproved"
    assert _violations(tool, clean_tree, capsys) == [f"VIOLATION {rule} {name}"]


def _add_uv_package(lock: str, name: str, version: str, depender: str) -> str:
    entry = (
        f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        f'sdist = {{ url = "https://files.pythonhosted.org/packages/{name}.tar.gz", '
        f'hash = "sha256:{"b" * 64}", size = 1 }}\n\n'
    )
    marker = f'name = "{depender}"\nversion = '
    start = lock.index(marker)
    source_end = lock.index("\n", lock.index("source = ", start)) + 1
    lock = (
        lock[:source_end] + f'dependencies = [\n    {{ name = "{name}" }},\n]\n' + lock[source_end:]
    )
    return lock.replace('[[package]]\nname = "pytest"', entry + '[[package]]\nname = "pytest"', 1)


def test_transitive_runtime_python_dependency_is_age_checked(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "oldpkg", "0.1.0", "cbor2")
    _write(clean_tree, "uv.lock", lock)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION stale oldpkg"]


def test_transitive_dev_python_dependency_is_licence_checked_but_age_exempt(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "gpl-old", "0.1.0", "pytest")
    _write(clean_tree, "uv.lock", lock)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION licence gpl-old"]


def _add_npm_package(lock: str, name: str, version: str, depender: str) -> str:
    entry = f"  {name}@{version}:\n    resolution: {{integrity: sha512-{'B' * 86}==}}\n\n"
    lock = lock.replace("packages:\n\n", "packages:\n\n" + entry, 1)
    lock = lock.replace(
        f"  {depender}: {{}}", f"  {depender}:\n    dependencies:\n      {name}: {version}"
    )
    return lock.replace("snapshots:\n\n", f"snapshots:\n\n  {name}@{version}: {{}}\n\n", 1)


def test_transitive_runtime_npm_dependency_is_age_checked(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_npm_package(
        (clean_tree / "pnpm-lock.yaml").read_text(), "old-js", "1.0.0", "'@hpke/core@1.9.0'"
    )
    # A host-app importer, not a library: old-js is runtime but outside the web allow-list (A2).
    lock = lock.replace("  packages/teecustody-web:\n", "  examples/notes-app/web:\n", 1)
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION stale old-js"]


def test_transitive_dev_npm_dependency_is_licence_checked_at_its_locked_version(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_npm_package(
        (clean_tree / "pnpm-lock.yaml").read_text(), "relicensed", "1.0.0", "typescript@5.9.3"
    )
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION licence relicensed"]


def _with_unlicensed_dev_package(clean_tree: Path) -> None:
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "nometa", "1.0.0", "pytest")
    _write(clean_tree, "uv.lock", lock)


def test_override_supplies_a_licence_missing_from_registry_metadata(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_unlicensed_dev_package(clean_tree)
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION licence nometa"]
    override = tool.LicenceOverride("MIT", "https://example.test/nometa/blob/abc123/LICENSE")
    monkeypatch.setattr(tool, "LICENCE_OVERRIDES", {"nometa==1.0.0": override})
    assert _violations(tool, clean_tree, capsys, offline=False) == []


def test_override_for_another_version_does_not_apply(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _with_unlicensed_dev_package(clean_tree)
    override = tool.LicenceOverride("MIT", "https://example.test/nometa/blob/abc123/LICENSE")
    monkeypatch.setattr(tool, "LICENCE_OVERRIDES", {"nometa==0.9.0": override})
    argv = ["--root", str(clean_tree), "--today", TODAY]
    assert tool.main(argv, fetch_json=recorded_fetch) == 1
    captured = capsys.readouterr()
    assert captured.out == "VIOLATION licence nometa\n"
    assert "nometa==0.9.0 does not match locked nometa==1.0.0" in captured.err


def test_override_cannot_relax_a_stated_non_osi_licence(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "gpl-old", "0.1.0", "pytest")
    _write(clean_tree, "uv.lock", lock)
    override = tool.LicenceOverride("MIT", "https://example.test/gpl-old/blob/abc123/LICENSE")
    monkeypatch.setattr(tool, "LICENCE_OVERRIDES", {"gpl-old==0.1.0": override})
    assert _violations(tool, clean_tree, capsys, offline=False) == ["VIOLATION licence gpl-old"]


def test_every_override_names_an_allowed_licence_and_pinned_evidence(tool: ModuleType) -> None:
    assert tool.LICENCE_OVERRIDES
    for key, override in tool.LICENCE_OVERRIDES.items():
        name, _, version = key.partition("==")
        assert name, key
        assert version, key
        assert tool.licence_allowed(override.spdx), key
        assert re.fullmatch(
            r"https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/LICENSE", override.evidence
        )


# INC-2 (T-05): HPKE dependency closure, exact HPKE pins, web runtime closure (ADR 0011 C3, SR-9).

INC2_CASES = [
    ("web-runtime-closure", ["VIOLATION web-runtime-closure rogue-shim"]),
    (
        "hpke-closure",
        [
            "VIOLATION crypto-unapproved @hpke/dhkem-x25519",
            "VIOLATION web-runtime-closure @hpke/dhkem-x25519",
            "VIOLATION hpke-closure @hpke/dhkem-x25519",
        ],
    ),
    (
        "crypto-unpinned-range-hpke-core",
        ["VIOLATION crypto-unpinned @hpke/core", "VIOLATION crypto-unpinned-range @hpke/core"],
    ),
    (
        "crypto-unpinned-range-pyhpke",
        ["VIOLATION crypto-unpinned pyhpke", "VIOLATION crypto-unpinned-range pyhpke"],
    ),
    ("pyhpke-runtime-deps", ["VIOLATION pyhpke-runtime-deps typing-extensions"]),
]


@pytest.mark.parametrize(("case", "expected"), INC2_CASES)
def test_inc2_rule_reports_its_violation_and_fails(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    case: str,
    expected: list[str],
) -> None:
    _apply_overlay(clean_tree, case)
    assert _violations(tool, clean_tree, capsys) == expected


GATEWAY_MANIFEST = "examples/notes-app/gateway/pyproject.toml"


def test_gateway_manifest_is_discovered(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        clean_tree,
        GATEWAY_MANIFEST,
        '[project]\nname = "notes-gateway"\nversion = "0.1.0"\ndependencies = ["pyaes==1.6.1"]\n',
    )
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION forbidden pyaes"]


def test_web_manifest_is_discovered(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        clean_tree,
        WEB_MANIFEST,
        '{"name": "@teecustody/web", "dependencies": {"@hpke/common": "~1.9.0"}}',
    )
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION crypto-unpinned @hpke/common",
        "VIOLATION crypto-unpinned-range @hpke/common",
        "VIOLATION hpke-common-direct packages/teecustody-web/package.json",
    ]


@pytest.mark.parametrize(
    "name", ["@hpke/dhkem-x448", "@hpke/chacha20poly1305", "@noble/hashes", "tweetnacl"]
)
def test_banned_package_in_web_runtime_closure_fails_hpke_closure(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    lock = _add_npm_package(
        (clean_tree / "pnpm-lock.yaml").read_text(), name, "1.0.0", "'@hpke/core@1.9.0'"
    )
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == [
        f"VIOLATION crypto-unapproved {name}",
        f"VIOLATION web-runtime-closure {name}",
        f"VIOLATION hpke-closure {name}",
    ]


def test_banned_package_in_library_runtime_closure_fails_hpke_closure(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "tweetnacl", "1.0.0", "cbor2")
    _write(clean_tree, "uv.lock", lock)
    assert _violations(tool, clean_tree, capsys) == [
        "VIOLATION crypto-unapproved tweetnacl",
        "VIOLATION hpke-closure tweetnacl",
    ]


def test_banned_package_reached_only_from_dev_tooling_is_not_an_hpke_closure_violation(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_npm_package(
        (clean_tree / "pnpm-lock.yaml").read_text(), "tweetnacl", "1.0.0", "typescript@5.9.3"
    )
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION crypto-unapproved tweetnacl"]


def test_web_runtime_closure_includes_the_linked_core_closure(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _apply_overlay(clean_tree, "web-runtime-closure")
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    lock = lock.replace("      rogue-shim: 1.0.0\n", "", 1)
    lock = lock.replace(
        "  packages/teecustody-core: {}\n",
        "  packages/teecustody-core:\n    dependencies:\n"
        "      rogue-shim:\n        specifier: 1.0.0\n        version: 1.0.0\n",
        1,
    )
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION web-runtime-closure rogue-shim"]


def test_dev_only_workspace_link_does_not_extend_the_web_runtime_closure(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _apply_overlay(clean_tree, "web-runtime-closure")
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    lock = lock.replace("      rogue-shim: 1.0.0\n", "", 1)
    lock = lock.replace(
        "  packages/teecustody-core: {}\n",
        "  packages/teecustody-core:\n    dependencies:\n"
        "      rogue-shim:\n        specifier: 1.0.0\n        version: 1.0.0\n",
        1,
    )
    lock = lock.replace(
        "      '@teecustody/core':\n        specifier: workspace:*\n",
        "    devDependencies:\n      '@teecustody/core':\n        specifier: workspace:*\n",
        1,
    )
    _write(clean_tree, "pnpm-lock.yaml", lock)
    assert _violations(tool, clean_tree, capsys) == []


def test_unnamed_npm_manifest_has_no_library_closure(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(clean_tree, WEB_MANIFEST, '{"private": true}')
    assert _violations(tool, clean_tree, capsys) == []
    assert tool.WEB_PACKAGE not in tool.load_repo(clean_tree).library_closures


# CI wiring (T-05; WAVES.md "Orchestrator actions" item 1, API-TL TL-7). PyYAML is not a dependency,
# so the workflow is read line by line.
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
CI_COMMANDS = [
    "uv run pytest -q packages/teecustody-py packages/teecustody-sim examples/notes-app/gateway"
    " tests && pnpm -r test && uv run pytest -q spec/vectors",
    "uv run ruff check . && uv run ruff format --check . && uv run mypy --strict"
    " packages/teecustody-py/src packages/teecustody-sim/src examples/notes-app/gateway/src"
    " && pnpm -r lint && pnpm -r typecheck"
    " && uvx semgrep==1.178.0 --config .semgrep.yml --error --metrics=off --disable-nosem",
    "uv run pytest --cov=teecustody --cov=teecustody_sim --cov=notes_gateway"
    " --cov-report=term-missing packages/teecustody-py packages/teecustody-sim"
    " examples/notes-app/gateway && pnpm -r coverage",
]


def _ci_job(name: str) -> list[str]:
    """The lines of one job under `jobs:` (two-space key), without the key line."""
    lines = CI_WORKFLOW.read_text().splitlines()
    start = lines.index(f"  {name}:") + 1
    end = next((i for i in range(start, len(lines)) if re.match(r"^  \S", lines[i])), len(lines))
    return lines[start:end]


@pytest.mark.parametrize(
    ("job", "command"), list(zip(["test", "lint", "coverage"], CI_COMMANDS, strict=True))
)
def test_ci_runs_the_framework_commands_verbatim(job: str, command: str) -> None:
    assert f"        run: {command}" in _ci_job(job)


def test_ci_has_a_browser_job_without_secrets() -> None:
    job = _ci_job("browser")
    steps = [line.strip() for line in job]
    assert "if: github.event_name == 'push' || github.event_name == 'pull_request'" in steps
    assert "timeout-minutes: 30" in steps
    for run in [
        "uv sync --locked",
        "pnpm install --frozen-lockfile",
        "pnpm --filter @teecustody/web exec playwright install --with-deps chromium firefox webkit",
        "pnpm --filter @teecustody/web run test:browser",
    ]:
        assert f"- run: {run}" in steps or f"run: {run}" in steps, run
    for action in ["actions/checkout@", "astral-sh/setup-uv@", "pnpm/action-setup@"]:
        assert any(action in step for step in steps), action
    assert 'node-version: "22"' in steps
    assert not any("secrets." in line for line in job)

    # checkout, setup-uv, pnpm and node steps (with their pins) are identical to the `test` job's.
    def setup(lines: list[str]) -> list[str]:
        start = lines.index("    steps:")
        return lines[start : lines.index("          cache: pnpm", start) + 1]

    assert setup(job) == setup(_ci_job("test"))


def test_gitleaks_allowlist_holds_exactly_the_synthetic_vector_files() -> None:
    config = tomllib.loads((REPO / ".gitleaks.toml").read_text())
    assert config == {
        "extend": {"useDefault": True},
        "allowlist": {
            "paths": [
                r"^spec/vectors/channel/suite\.cbor$",
                r"^tests/fixtures/rfc9180/test-vectors\.json$",
            ],
        },
    }


def test_core_has_no_runtime_dependencies_not_even_hpke(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(
        clean_tree,
        "packages/teecustody-core/package.json",
        '{"name": "@teecustody/core", "dependencies": {"@hpke/core": "1.9.0"}}',
    )
    assert _violations(tool, clean_tree, capsys) == ["VIOLATION core-runtime-deps @hpke/core"]


# A3 (D-045, ADR 0011 C6): @hpke/common only through @hpke/core; HPKE only at signed versions.


def test_hpke_common_in_any_manifest_group_is_reported_with_its_manifest_path(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = json.loads((clean_tree / "package.json").read_text())
    manifest["devDependencies"]["@hpke/common"] = "1.10.1"
    _write(clean_tree, "package.json", json.dumps(manifest))
    core = json.loads((clean_tree / "packages/teecustody-core/package.json").read_text())
    core["optionalDependencies"] = {"@hpke/common": "1.10.1"}
    _write(clean_tree, "packages/teecustody-core/package.json", json.dumps(core))
    lines = _violations(tool, clean_tree, capsys)
    assert "VIOLATION hpke-common-direct package.json" in lines
    assert "VIOLATION hpke-common-direct packages/teecustody-core/package.json" in lines


@pytest.mark.parametrize(("name", "signed"), [("@hpke/core", "1.9.0"), ("@hpke/common", "1.10.1")])
def test_npm_hpke_package_at_an_unsigned_version_is_reported(
    tool: ModuleType, clean_tree: Path, capsys: pytest.CaptureFixture[str], name: str, signed: str
) -> None:
    assert tool.C6_SIGNED_VERSIONS[name] == signed
    lock = (clean_tree / "pnpm-lock.yaml").read_text()
    entry = f"  '{name}@9.9.9':\n    resolution: {{integrity: sha512-{'B' * 86}==}}\n\n"
    _write(clean_tree, "pnpm-lock.yaml", lock.replace("packages:\n\n", "packages:\n\n" + entry, 1))
    assert _violations(tool, clean_tree, capsys) == [f"VIOLATION crypto-unsigned-version {name}"]


@pytest.mark.parametrize(
    ("version", "expected"),
    [("0.6.5", []), ("0.6.4", ["VIOLATION crypto-unsigned-version pyhpke"])],
)
def test_pyhpke_is_accepted_only_at_its_signed_version(
    tool: ModuleType,
    clean_tree: Path,
    capsys: pytest.CaptureFixture[str],
    version: str,
    expected: list[str],
) -> None:
    assert tool.C6_SIGNED_VERSIONS == {
        "@hpke/core": "1.9.0",
        "@hpke/common": "1.10.1",
        "pyhpke": "0.6.5",
    }
    lock = _add_uv_package((clean_tree / "uv.lock").read_text(), "pyhpke", version, "cbor2")
    _write(clean_tree, "uv.lock", lock)
    assert _violations(tool, clean_tree, capsys) == expected


# T-37 (D-049, DEBT-3): h11 0.16.0 is admitted past the age rule only as uvicorn's dependency in the
# notes-gateway member. `--today 2026-10-25` puts h11's 2025-04-24 release outside the window.

H11_TODAY = "2026-10-25"
H11_RELEASED = "2025-04-24T00:00:00.000000Z"
UVICORN_RELEASED = "2026-09-25T00:00:00.000000Z"


def _pypi_document(licence: str, released: str, version: str) -> dict[str, object]:
    info: dict[str, object] = {
        "license_expression": licence,
        "license": None,
        "classifiers": [],
        "version": version,
    }
    return {"info": info, "urls": [{"upload_time_iso_8601": released}]}


def _h11_fetch(h11_licence: str = "MIT") -> Callable[[str], object]:
    """The recorded registry plus h11 (2025-04-24) and uvicorn (recent)."""
    documents = {
        "h11": _pypi_document(h11_licence, H11_RELEASED, "0.16.0"),
        "uvicorn": _pypi_document("BSD-3-Clause", UVICORN_RELEASED, "0.54.0"),
    }

    def fetch(url: str) -> object:
        name = url.removeprefix("https://pypi.org/pypi/").split("/", 1)[0]
        if url.startswith("https://pypi.org/pypi/") and name in documents:
            return documents[name]
        return recorded_fetch(url)

    return fetch


def _uv_entry(name: str, version: str, source: str, dependencies: list[str]) -> str:
    entry = f'[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {source}\n'
    if source.startswith("{ registry"):
        url = f"https://files.pythonhosted.org/packages/{name}-{version}.tar.gz"
        entry += f'sdist = {{ url = "{url}", hash = "sha256:{"a" * 64}", size = 1 }}\n'
    if dependencies:
        entry += "dependencies = [\n" + "".join(f'    {{ name = "{d}" }},\n' for d in dependencies)
        entry += "]\n"
    return entry + "\n"


def _gateway_lock(clean_lock: str) -> str:
    """The clean lock plus notes-gateway -> uvicorn -> h11 0.16.0, shaped like the real uv.lock."""
    registry = '{ registry = "https://pypi.org/simple" }'
    lock = clean_lock.replace("members = [\n", 'members = [\n    "notes-gateway",\n', 1)
    lock = lock.replace(
        '    { name = "teecustody" },\n    { name = "teecustody-sim" },\n',
        '    { name = "notes-gateway" },\n    { name = "teecustody" },\n'
        '    { name = "teecustody-sim" },\n',
        1,
    )
    lock = lock.replace(
        '[[package]]\nname = "pytest"',
        _uv_entry("h11", "0.16.0", registry, [])
        + _uv_entry(
            "notes-gateway",
            "0.1.0",
            '{ editable = "examples/notes-app/gateway" }',
            ["teecustody", "uvicorn"],
        )
        + '[[package]]\nname = "pytest"',
        1,
    )
    return lock + "\n" + _uv_entry("uvicorn", "0.54.0", registry, ["h11"]).rstrip("\n") + "\n"


def _gateway_manifest(*dependencies: str) -> str:
    return (
        '[project]\nname = "notes-gateway"\nversion = "0.1.0"\n'
        f"dependencies = {json.dumps(list(dependencies))}\n"
    )


@pytest.fixture
def gateway_tree(clean_tree: Path) -> Path:
    """Shaped like the real tree: the gateway manifest declares uvicorn directly."""
    _write(clean_tree, "uv.lock", _gateway_lock((clean_tree / "uv.lock").read_text()))
    _write(clean_tree, GATEWAY_MANIFEST, _gateway_manifest("teecustody==0.1.0", "uvicorn==0.54.0"))
    return clean_tree


def _h11_violations(
    tool: ModuleType, root: Path, capsys: pytest.CaptureFixture[str], h11_licence: str = "MIT"
) -> list[str]:
    argv = ["--root", str(root), "--today", H11_TODAY]
    status = tool.main(argv, fetch_json=_h11_fetch(h11_licence))
    lines = capsys.readouterr().out.splitlines()
    assert status == (1 if lines else 0)
    return lines


def test_h11_0_16_0_reached_only_through_uvicorn_in_the_gateway_is_not_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _h11_violations(tool, gateway_tree, capsys) == []


@pytest.mark.parametrize("case", ["h11-other-version", "h11-library-closure", "h11-direct-gateway"])
def test_h11_outside_the_exact_exception_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str], case: str
) -> None:
    _apply_overlay(gateway_tree, case)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_other_stale_packages_in_the_gateway_closure_are_still_reported(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (gateway_tree / "uv.lock").read_text()
    lock = lock.replace(
        '    { name = "uvicorn" },\n', '    { name = "oldpkg" },\n    { name = "uvicorn" },\n', 1
    )
    lock = lock.replace(
        '[[package]]\nname = "pytest"',
        _uv_entry("oldpkg", "0.1.0", '{ registry = "https://pypi.org/simple" }', [])
        + '[[package]]\nname = "pytest"',
        1,
    )
    _write(gateway_tree, "uv.lock", lock)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale oldpkg"]


def test_the_h11_exception_covers_age_only_not_the_licence(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lines = _h11_violations(tool, gateway_tree, capsys, h11_licence="GPL-3.0-only")
    assert lines == ["VIOLATION licence h11"]


def test_h11_through_uvicorn_is_stale_when_the_gateway_member_is_not_locked(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (gateway_tree / "uv.lock").read_text().replace('    "notes-gateway",\n', "", 1)
    lock = lock.replace('    { name = "notes-gateway" },\n', "", 1)
    start = lock.index('[[package]]\nname = "notes-gateway"')
    lock = lock[:start] + lock[lock.index("[[package]]", start + 1) :]
    _write(gateway_tree, "uv.lock", lock)
    _write(gateway_tree, GATEWAY_MANIFEST, _gateway_manifest("uvicorn==0.54.0"))
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_h11_through_uvicorn_in_the_library_closure_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    library = '    { name = "cbor2" },\n    { name = "cryptography" },\n'
    lock = (gateway_tree / "uv.lock").read_text()
    _write(
        gateway_tree, "uv.lock", lock.replace(library, library + '    { name = "uvicorn" },\n', 1)
    )
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_an_npm_package_named_h11_gets_no_age_exception(
    tool: ModuleType, gateway_tree: Path
) -> None:
    pnpm = (gateway_tree / "pnpm-lock.yaml").read_text()
    lock = _add_npm_package(pnpm, "h11", "0.16.0", "'@hpke/core@1.9.0'")
    _write(gateway_tree, "pnpm-lock.yaml", lock)
    repo = tool.load_repo(gateway_tree)
    assert ("npm", "h11") in repo.runtime
    assert tool._age_exempt(repo, "pypi", "h11")
    assert not tool._age_exempt(repo, "npm", "h11")


def test_h11_locked_at_a_second_version_as_well_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (gateway_tree / "uv.lock").read_text()
    second = _uv_entry("h11", "0.14.0", '{ registry = "https://pypi.org/simple" }', [])
    lock = lock.replace('[[package]]\nname = "h11"', second + '[[package]]\nname = "h11"', 1)
    _write(gateway_tree, "uv.lock", lock)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_h11_declared_directly_in_the_gateway_manifest_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _gateway_manifest("teecustody==0.1.0", "uvicorn==0.54.0", "h11==0.16.0")
    _write(gateway_tree, GATEWAY_MANIFEST, manifest)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def _add_lock_edge(lock: str, depender: str, dependency: str) -> str:
    start = lock.index(f'[[package]]\nname = "{depender}"\nversion')
    at = lock.index("dependencies = [\n", start) + len("dependencies = [\n")
    assert "[[package]]" not in lock[start + 1 : at]
    return lock[:at] + f'    {{ name = "{dependency}" }},\n' + lock[at:]


@pytest.mark.parametrize(
    ("library", "dependency"),
    [
        ("teecustody", "notes-gateway"),
        ("teecustody-sim", "notes-gateway"),
        ("teecustody-sim", "uvicorn"),
    ],
)
def test_h11_in_the_full_runtime_closure_of_a_library_is_still_stale(
    tool: ModuleType,
    gateway_tree: Path,
    capsys: pytest.CaptureFixture[str],
    library: str,
    dependency: str,
) -> None:
    lock = _add_lock_edge((gateway_tree / "uv.lock").read_text(), library, dependency)
    _write(gateway_tree, "uv.lock", lock)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_a_registry_package_named_like_the_gateway_member_gets_no_exception(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (gateway_tree / "uv.lock").read_text()
    lock = lock.replace('    "notes-gateway",\n', '    "relay",\n', 1)
    lock = lock.replace('    { name = "notes-gateway" },\n', '    { name = "relay" },\n', 1)
    member = '[[package]]\nname = "notes-gateway"\nversion = "0.1.0"\n'
    lock = lock.replace(member, '[[package]]\nname = "relay"\nversion = "0.1.0"\n', 1)
    lock = lock.replace('    { name = "uvicorn" },\n', '    { name = "notes-gateway" },\n', 1)
    registry = '{ registry = "https://pypi.org/simple" }'
    impostor = _uv_entry("notes-gateway", "9.9.9", registry, ["uvicorn"])
    lock = lock.replace('[[package]]\nname = "pytest"', impostor + '[[package]]\nname = "pytest"')
    _write(gateway_tree, "uv.lock", lock)
    manifest = _gateway_manifest("teecustody==0.1.0", "notes-gateway==9.9.9")
    _write(gateway_tree, GATEWAY_MANIFEST, manifest.replace('"notes-gateway"\n', '"relay"\n', 1))
    repo = tool.load_repo(gateway_tree)
    assert "relay" in repo.workspace
    assert "notes-gateway" not in repo.workspace
    assert ("pypi", "h11") in repo.runtime
    assert not tool._age_exempt(repo, "pypi", "h11")


def test_uvicorn_declared_by_a_library_manifest_but_not_locked_still_makes_h11_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = gateway_tree / "packages" / "teecustody-py" / "pyproject.toml"
    text = manifest.read_text().replace('"cbor2==6.1.4"]', '"cbor2==6.1.4", "uvicorn==0.54.0"]')
    assert "uvicorn" in text
    _write(gateway_tree, "packages/teecustody-py/pyproject.toml", text)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_h11_through_uvicorn_from_another_workspace_member_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = _add_lock_edge(
        (gateway_tree / "uv.lock").read_text(), "tee-custody-workspace", "uvicorn"
    )
    _write(gateway_tree, "uv.lock", lock)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_h11_through_uvicorn_outside_the_locked_gateway_closure_is_still_stale(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    lock = (gateway_tree / "uv.lock").read_text()
    gateway = 'dependencies = [\n    { name = "teecustody" },\n    { name = "uvicorn" },\n]\n'
    lock = lock.replace(gateway, 'dependencies = [\n    { name = "teecustody" },\n]\n', 1)
    _write(gateway_tree, "uv.lock", lock)
    root = (gateway_tree / "pyproject.toml").read_text()
    root = root.replace('"teecustody-sim"]', '"teecustody-sim", "uvicorn==0.54.0"]', 1)
    assert "uvicorn" in root
    _write(gateway_tree, "pyproject.toml", root)
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def _unlocked_manifest(name: str, *dependencies: str) -> str:
    return (
        f'[project]\nname = "{name}"\nversion = "0.1.0"\n'
        f"dependencies = {json.dumps(list(dependencies))}\n"
    )


@pytest.mark.parametrize("declared", ["uvicorn==0.54.0", "notes-gateway==0.1.0"])
def test_a_manifest_outside_the_lock_declaring_uvicorn_or_the_gateway_blocks_the_exception(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str], declared: str
) -> None:
    _write(gateway_tree, "packages/foo/pyproject.toml", _unlocked_manifest("foo", declared))
    assert _h11_violations(tool, gateway_tree, capsys) == ["VIOLATION stale h11"]


def test_only_uv_workspace_members_are_roots_not_manifest_names_that_collide_with_the_lock(
    tool: ModuleType, gateway_tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # notes-gateway -> uvicorn-proxy (registry) -> uvicorn -> h11, and an unrelated unlocked
    # manifest that happens to be named uvicorn-proxy: still only the gateway reaches uvicorn.
    lock = (gateway_tree / "uv.lock").read_text()
    gateway = '    { name = "teecustody" },\n    { name = "uvicorn" },\n'
    lock = lock.replace(gateway, '    { name = "teecustody" },\n    { name = "uvicorn-proxy" },\n')
    proxy = _uv_entry(
        "uvicorn-proxy", "1.0.0", '{ registry = "https://pypi.org/simple" }', ["uvicorn"]
    )
    lock = lock.replace('[[package]]\nname = "pytest"', proxy + '[[package]]\nname = "pytest"', 1)
    _write(gateway_tree, "uv.lock", lock)
    _write(gateway_tree, "packages/proxy/pyproject.toml", _unlocked_manifest("uvicorn-proxy"))
    repo = tool.load_repo(gateway_tree)
    assert "uvicorn-proxy" in repo.workspace
    assert "uvicorn-proxy" not in repo.uv_members
    assert _h11_violations(tool, gateway_tree, capsys) == []
