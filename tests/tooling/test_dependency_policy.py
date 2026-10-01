"""T-14: tools/dependency_policy.py enforces framework.yaml dependency_policy (SR-9, D-019)."""

import importlib.util
import json
import re
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
