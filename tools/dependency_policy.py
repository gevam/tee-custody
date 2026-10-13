"""Dependency policy check (SR-9, NFR-6; framework.yaml security.dependency_policy, D-019).

Reads uv.lock, pnpm-lock.yaml and the Python and npm manifests at the repository root and under
packages/, prints one ``VIOLATION <rule> <package>`` line per violation and exits 1 if there is any.
"""

import argparse
import calendar
import datetime as dt
import json
import posixpath
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN = frozenset(
    {"pycrypto", "pyaes", "tinyec", "crypto-js", "node-forge", "elliptic", "sjcl"},
)
SIM_PACKAGE = "teecustody-sim"
LIBRARY_PACKAGE = "teecustody"
CORE_PACKAGE = "@teecustody/core"
WEB_PACKAGE = "@teecustody/web"
PYHPKE = "pyhpke"
CBOR_X = "cbor-x"
# framework.yaml forbidden_dependencies items that are conditional rather than lock-wide bans.
FORBIDDEN_CONDITIONAL = {SIM_PACKAGE: "sim-in-library"}

KNOWN_CRYPTO = frozenset(
    {
        "pycryptodome",
        "pycryptodomex",
        "pynacl",
        "pysodium",
        "libnacl",
        "pyjwt",
        "python-jose",
        "josepy",
        "jwcrypto",
        "authlib",
        "ecdsa",
        "rsa",
        "tinyec",
        "pyaes",
        "pycrypto",
        "jose",
        "node-jose",
        "jsonwebtoken",
        "jws",
        "jwa",
        "tweetnacl",
        "libsodium-wrappers",
        "sodium-native",
        "node-forge",
        "elliptic",
        "crypto-js",
        "sjcl",
        # Pure-Python / pure-JS X25519, Ed25519, AES, HKDF and NaCl implementations.
        "pure25519",
        "ed25519",
        "x25519",
        "curve25519-donna",
        "hkdf",
        "futoin-hkdf",
        "js-nacl",
        "tweetnacl-util",
        "ed2curve",
        "aes-js",
        "asmcrypto.js",
    },
)
# @hpke/* other than the approved @hpke/core are pure-JS KEM/AEAD add-ons (e.g. @hpke/dhkem-x25519).
KNOWN_CRYPTO_PREFIXES = ("@noble/", "@stablelib/", "@hpke/")
APPROVED_CRYPTO = frozenset(
    {"cryptography", "pyhpke", "tink", "cbor2", "@hpke/core", "@hpke/common", "cbor-x"},
)
CORE_RUNTIME_ALLOWED: frozenset[str] = frozenset()  # Core has no runtime dependencies (C3, A2)
# ADR 0011 C3: the web runtime closure is Core plus the @hpke/core distribution, nothing else.
WEB_RUNTIME_ALLOWED = frozenset({CORE_PACKAGE, "@hpke/core", "@hpke/common"})
# ADR 0011 C3: pure-JS KEM/AEAD and curve packages never reach a library runtime closure.
HPKE_CLOSURE_BANNED = frozenset(
    {"@hpke/dhkem-x25519", "@hpke/dhkem-x448", "@hpke/chacha20poly1305", "tweetnacl"},
)
HPKE_CLOSURE_BANNED_PREFIXES = ("@noble/",)
EXACT_PIN_REQUIRED = frozenset({"@hpke/core", "@hpke/common", PYHPKE})
HPKE_COMMON = "@hpke/common"  # admitted only transitively, through @hpke/core (D-045)
# Versions signed in ADR 0011's C6 amendments (D-045); a change lands only with its new C6 sign-off.
C6_SIGNED_VERSIONS = {"@hpke/core": "1.9.0", HPKE_COMMON: "1.10.1", PYHPKE: "0.6.5"}
PYHPKE_RUNTIME_ALLOWED = frozenset({"cryptography"})

LICENCES = frozenset(
    {
        "MIT",
        "MIT-0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "ISC",
        "MPL-2.0",
        "PSF-2.0",
        "Python-2.0",
        "0BSD",
        "Unlicense",
    },
)
CLASSIFIER_LICENCES = {
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
}
STALE_MONTHS = 18


@dataclass(frozen=True)
class AgeException:
    """A human-decided admission of one exact version past the age rule, on one path only."""

    version: str
    member: str  # the workspace member whose runtime closure may contain the package
    via: str  # the package through which every path from a shipped root must pass
    decision: str


# D-049 (human, 2026-10-13); DEBT-3, expires INC-5. Re-checked at every lock change.
AGE_EXCEPTIONS: Final = {
    "h11": AgeException(version="0.16.0", member="notes-gateway", via="uvicorn", decision="D-049"),
}


@dataclass(frozen=True)
class LicenceOverride:
    """A reviewed licence for one exact version whose registry metadata states none."""

    spdx: str
    evidence: str  # upstream LICENSE at the commit of the released tag


# Keyed by exact `name==version`. Applied only when the registry metadata states no licence at all;
# never when it states one (allowed or not), and never to another version.
LICENCE_OVERRIDES: dict[str, LicenceOverride] = {
    # PyPI metadata for 1.1.0 has no license, license_expression or classifier. Tag 1.1.0 is
    # commit 70d9435779df27a522b146f2c5dee06ccacae373; its LICENSE is MIT (reviewed 2026-10-01).
    "mypy-extensions==1.1.0": LicenceOverride(
        "MIT",
        "https://github.com/python/mypy_extensions/blob/"
        "70d9435779df27a522b146f2c5dee06ccacae373/LICENSE",
    ),
}

RULE_ORDER = (
    "lock-unparseable",
    "lock-inconsistent",
    "forbidden",
    "crypto-unapproved",
    "crypto-unpinned",
    "crypto-unpinned-range",
    "crypto-unsigned-version",
    "sim-in-library",
    "core-runtime-deps",
    "web-runtime-closure",
    "hpke-closure",
    "pyhpke-runtime-deps",
    "hpke-common-direct",
    "cbor-x-unused",
    "licence",
    "stale",
)

PYPI = "pypi"
NPM = "npm"
UV_LOCK = "uv.lock"
PNPM_LOCK = "pnpm-lock.yaml"
NPM_RUNTIME_FIELDS = ("dependencies", "peerDependencies", "optionalDependencies")
NPM_ALL_FIELDS = (*NPM_RUNTIME_FIELDS, "devDependencies")
PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)")
PY_EXACT = re.compile(r"^==\s*([A-Za-z0-9.+!_-]+)$")
NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
# pnpm-lock.yaml v9 as pnpm writes it: two-space indentation, one entry per key line. Anything else
# (re-indented, hand-edited, a newer layout) is reported as unparseable rather than read leniently.
PNPM_TOP = re.compile(r"^(?P<key>[A-Za-z][\w-]*):(?:\s.*)?$")
PNPM_ENTRY = re.compile(r"^  (['\"]?)(?P<key>[^'\"\s][^'\"]*?)\1:(?:\s*\{\})?\s*$")
PNPM_GROUP = re.compile(r"^    (?P<group>[A-Za-z]+):\s*$")
PNPM_DEP = re.compile(r"^      (['\"]?)(?P<name>[^'\"\s][^'\"]*?)\1:(?:\s+(?P<version>\S+))?\s*$")
PNPM_IMPORTER_FIELD = re.compile(r"^        (?P<field>specifier|version):\s+(?P<value>\S+)\s*$")
PNPM_LIST_ITEM = re.compile(r"^      - \S")
PNPM_INTEGRITY = re.compile(r"integrity:\s*sha(?:256|384|512)-")
PNPM_IMPORTER_GROUPS = frozenset({*NPM_ALL_FIELDS})
PNPM_EDGE_GROUPS = frozenset({"dependencies", "optionalDependencies"})

FetchJson = Callable[[str], object]
Violation = tuple[str, str]
Node = tuple[str, str]  # (ecosystem, name)


@dataclass(frozen=True)
class Dependency:
    """A dependency declared in a manifest."""

    name: str
    spec: str
    ecosystem: str
    shipped: bool


@dataclass(frozen=True)
class Locked:
    """A package resolved in a lock file."""

    name: str
    version: str
    ecosystem: str
    hashed: bool


@dataclass
class LockData:
    """What one lock file contributes; ``errors`` makes the check fail closed."""

    locked: list[Locked] = field(default_factory=list)
    graph: dict[str, set[str]] = field(default_factory=dict)
    runtime_graph: dict[str, set[str]] = field(default_factory=dict)
    runtime_roots: set[str] = field(default_factory=set)
    # Per pnpm importer path: runtime name@version roots, and runtime `link:` importer paths.
    importer_roots: dict[str, set[str]] = field(default_factory=dict)
    importer_links: dict[str, set[str]] = field(default_factory=dict)
    members: set[str] = field(default_factory=set)
    errors: set[Violation] = field(default_factory=set)


@dataclass(frozen=True)
class Repo:
    """Everything the rules read from one repository tree."""

    locked: tuple[Locked, ...]
    direct: tuple[Dependency, ...]
    uv_graph: dict[str, set[str]]
    uv_runtime_graph: dict[str, set[str]]
    runtime: frozenset[Node]
    library_closures: dict[str, frozenset[str]]  # library package -> names in its runtime closure
    npm_manifests: tuple[dict[str, Any], ...]
    npm_manifest_paths: tuple[str, ...]  # repository-relative, aligned with npm_manifests
    workspace: frozenset[str]
    lock_errors: frozenset[Violation]


def normalise_python(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_registry_json(url: str) -> object:
    """The only network access: HTTPS GET of a public registry document."""
    if not url.startswith(("https://pypi.org/", "https://registry.npmjs.org/")):
        raise ValueError(f"refusing to fetch {url}")
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310 - https host checked
        return json.load(response)


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _parse_uv_lock(path: Path) -> LockData:
    lock = LockData()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        packages = data["package"]
        if not isinstance(packages, list) or not packages:
            raise ValueError("no packages")
        lock.members = {normalise_python(m) for m in data.get("manifest", {}).get("members", [])}
        for package in packages:
            _add_uv_package(lock, package)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        lock.errors.add(("lock-unparseable", UV_LOCK))
    return lock


def _add_uv_package(lock: LockData, package: dict[str, Any]) -> None:
    name = normalise_python(package["name"])
    hashes = [package.get("sdist", {}).get("hash")]
    hashes += [wheel.get("hash") for wheel in package.get("wheels", [])]
    lock.locked.append(Locked(name, str(package.get("version", "")), PYPI, any(hashes)))
    runtime = [normalise_python(edge["name"]) for edge in package.get("dependencies", [])]
    for group in package.get("optional-dependencies", {}).values():
        runtime += [normalise_python(edge["name"]) for edge in group]
    dev = [
        normalise_python(edge["name"])
        for group in package.get("dev-dependencies", {}).values()
        for edge in group
    ]
    lock.runtime_graph[name] = set(runtime)
    lock.graph[name] = set(runtime) | set(dev)


def _base_version(version: str) -> str:
    return version.split("(", 1)[0]


def _split_pnpm_key(key: str) -> tuple[str, str]:
    spec = _base_version(key)
    at = spec.rfind("@")
    if at <= 0:
        raise ValueError(f"no version in {key}")
    return spec[:at], spec[at + 1 :]


class _PnpmParser:
    """Line-based reader for the importers, packages and snapshots sections of pnpm-lock.yaml."""

    def __init__(self) -> None:
        self.lock = LockData()
        self.section = ""
        self.entry: str | None = None
        self.group: str | None = None
        self.dep: str | None = None
        self.importer_deps: list[tuple[str, str, str, str]] = []  # (importer, group, name, version)
        self.hashed: dict[str, bool] = {}

    def parse(self, text: str) -> LockData:
        for line in text.splitlines():
            if line.strip():
                self._line(line)
        for key, hashed in self.hashed.items():
            name, version = _split_pnpm_key(key)
            self.lock.locked.append(Locked(name, version, NPM, hashed))
        if self.importer_deps and not self.hashed:
            raise ValueError("importers declare dependencies but no package was parsed")
        return self.lock

    def _line(self, line: str) -> None:
        top = PNPM_TOP.match(line)
        if top:
            self.section, self.entry, self.group, self.dep = top.group("key"), None, None, None
        elif self.section == "importers":
            self._importer_line(line)
        elif self.section == "packages":
            self._package_line(line)
        elif self.section == "snapshots":
            self._snapshot_line(line)
        elif not line.startswith(" ") or not self.section:
            raise ValueError(f"unexpected line: {line!r}")

    def _new_entry(self, line: str) -> str | None:
        entry = PNPM_ENTRY.match(line)
        if entry:
            self.entry, self.group, self.dep = entry.group("key"), None, None
            return self.entry
        return None

    def _importer_line(self, line: str) -> None:
        group = PNPM_GROUP.match(line)
        dep = PNPM_DEP.match(line)
        value = PNPM_IMPORTER_FIELD.match(line)
        if self._new_entry(line) is not None:
            return
        if self.entry is None:
            raise ValueError(f"importer line before an importer: {line!r}")
        if group and group.group("group") in PNPM_IMPORTER_GROUPS:
            self.group, self.dep = group.group("group"), None
        elif dep and self.group and dep.group("version") is None:
            self.dep = dep.group("name")
        elif value and self.group and self.dep:
            if value.group("field") != "version":
                return
            if value.group("value").startswith("link:"):
                if self.group != "devDependencies":
                    target = posixpath.join(self.entry, value.group("value")[len("link:") :])
                    links = self.lock.importer_links.setdefault(self.entry, set())
                    links.add(posixpath.normpath(target))
                return
            version = _base_version(value.group("value"))
            self.importer_deps.append((self.entry, self.group, self.dep, version))
        else:
            raise ValueError(f"unexpected importer line: {line!r}")

    def _package_line(self, line: str) -> None:
        key = self._new_entry(line)
        if key is not None:
            _split_pnpm_key(key)
            self.hashed.setdefault(key, False)
        elif self.entry is None or not line.startswith("    "):
            raise ValueError(f"unexpected package line: {line!r}")
        elif PNPM_INTEGRITY.search(line):
            self.hashed[self.entry] = True

    def _snapshot_line(self, line: str) -> None:
        key = self._new_entry(line)
        if key is not None:
            name, version = _split_pnpm_key(key)
            self.lock.graph.setdefault(f"{name}@{version}", set())
            return
        group = PNPM_GROUP.match(line)
        dep = PNPM_DEP.match(line)
        if self.entry is None or not line.startswith("    "):
            raise ValueError(f"unexpected snapshot line: {line!r}")
        if group:
            self.group = group.group("group")
        elif self.group in PNPM_EDGE_GROUPS and dep and dep.group("version"):
            version = dep.group("version")
            if not version.startswith("link:"):
                name, base = _split_pnpm_key(self.entry)
                edge = f"{dep.group('name')}@{_base_version(version)}"
                self.lock.graph.setdefault(f"{name}@{base}", set()).add(edge)
        elif self.group in PNPM_EDGE_GROUPS or not (
            PNPM_LIST_ITEM.match(line) or line.startswith("    ")
        ):
            raise ValueError(f"unexpected snapshot line: {line!r}")


def _parse_pnpm_lock(path: Path) -> LockData:
    parser = _PnpmParser()
    try:
        lock = parser.parse(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        failed = LockData()
        failed.errors.add(("lock-unparseable", PNPM_LOCK))
        return failed
    keys = set(parser.hashed)
    for importer, group, name, version in parser.importer_deps:
        if f"{name}@{version}" not in keys:
            lock.errors.add(("lock-inconsistent", name))
        elif group != "devDependencies":
            lock.runtime_roots.add(f"{name}@{version}")
            lock.importer_roots.setdefault(importer, set()).add(f"{name}@{version}")
    return lock


def _python_manifest_deps(data: dict[str, Any]) -> Iterable[tuple[str, bool]]:
    project = data.get("project", {})
    for requirement in project.get("dependencies", []):
        yield requirement, True
    for group in project.get("optional-dependencies", {}).values():
        for requirement in group:
            yield requirement, True
    for requirement in data.get("build-system", {}).get("requires", []):
        yield requirement, True
    for group in data.get("dependency-groups", {}).values():
        for requirement in group:
            if isinstance(requirement, str):
                yield requirement, False


def _python_direct(paths: Iterable[Path]) -> list[Dependency]:
    direct: list[Dependency] = []
    for path in paths:
        for requirement, shipped in _python_manifest_deps(_read_toml(path)):
            match = PEP508_NAME.match(requirement)
            if match is None:
                continue
            spec = match.group(2).strip()
            direct.append(Dependency(normalise_python(match.group(1)), spec, PYPI, shipped))
    return direct


def _npm_direct(manifests: Iterable[dict[str, Any]]) -> list[Dependency]:
    direct: list[Dependency] = []
    for manifest in manifests:
        for group in NPM_ALL_FIELDS:
            for name, spec in manifest.get(group, {}).items():
                direct.append(Dependency(name, str(spec), NPM, group != "devDependencies"))
    return direct


def _closure(graph: dict[str, set[str]], starts: Iterable[str]) -> set[str]:
    seen: set[str] = set()
    pending = list(starts)
    while pending:
        for edge in graph.get(pending.pop(), set()):
            if edge not in seen:
                seen.add(edge)
                pending.append(edge)
    return seen


def _runtime_nodes(
    uv: LockData, pnpm: LockData, direct: list[Dependency], workspace: set[str]
) -> frozenset[Node]:
    py_roots = {d.name for d in direct if d.ecosystem == PYPI and d.shipped}
    for member in uv.members:
        py_roots |= uv.runtime_graph.get(member, set())
    py_nodes = py_roots | _closure(uv.runtime_graph, py_roots)
    npm_roots = set(pnpm.runtime_roots)
    npm_nodes = npm_roots | _closure(pnpm.graph, npm_roots)
    npm_names = {_split_pnpm_key(node)[0] for node in npm_nodes}
    npm_names |= {d.name for d in direct if d.ecosystem == NPM and d.shipped}
    nodes = {(PYPI, name) for name in py_nodes} | {(NPM, name) for name in npm_names}
    return frozenset(node for node in nodes if node[1] not in workspace)


def _npm_library_closures(
    root: Path, manifests: dict[Path, dict[str, Any]], pnpm: LockData
) -> dict[str, frozenset[str]]:
    """Runtime closure, by name, of every npm workspace package; workspace links are followed."""
    closures: dict[str, frozenset[str]] = {}
    for path, manifest in manifests.items():
        if "name" not in manifest:
            continue
        importer = path.parent.relative_to(root).as_posix()
        importers = {importer} | _closure(pnpm.importer_links, [importer])
        roots = {node for i in importers for node in pnpm.importer_roots.get(i, set())}
        nodes = roots | _closure(pnpm.graph, roots)
        closures[str(manifest["name"])] = frozenset(_split_pnpm_key(n)[0] for n in nodes)
    return closures


def load_repo(root: Path) -> Repo:
    pyprojects = [
        root / "pyproject.toml",
        *sorted(root.glob("packages/*/pyproject.toml")),
        root / "examples" / "notes-app" / "gateway" / "pyproject.toml",
    ]
    package_jsons = [root / "package.json", *sorted(root.glob("packages/*/package.json"))]
    manifests = {path: _read_json(path) for path in package_jsons if path.is_file()}
    npm_manifests = tuple(manifests.values())
    direct = _python_direct(pyprojects) + _npm_direct(npm_manifests)
    uv = _parse_uv_lock(root / UV_LOCK) if (root / UV_LOCK).is_file() else LockData()
    pnpm = _parse_pnpm_lock(root / PNPM_LOCK) if (root / PNPM_LOCK).is_file() else LockData()
    workspace = uv.members | {str(m["name"]) for m in npm_manifests if "name" in m}
    for path in pyprojects:
        name = _read_toml(path).get("project", {}).get("name")
        if name:
            workspace.add(normalise_python(name))
    errors = uv.errors | pnpm.errors
    for ecosystem, lock_name, path in (
        (PYPI, UV_LOCK, root / UV_LOCK),
        (NPM, PNPM_LOCK, root / PNPM_LOCK),
    ):
        declared = any(d.ecosystem == ecosystem and d.name not in workspace for d in direct)
        if declared and not path.is_file():
            errors.add(("lock-unparseable", lock_name))
    return Repo(
        locked=tuple(uv.locked + pnpm.locked),
        direct=tuple(direct),
        uv_graph=uv.graph,
        uv_runtime_graph=uv.runtime_graph,
        runtime=_runtime_nodes(uv, pnpm, direct, workspace),
        library_closures={
            LIBRARY_PACKAGE: frozenset(_closure(uv.runtime_graph, [LIBRARY_PACKAGE])),
            **_npm_library_closures(root, manifests, pnpm),
        },
        npm_manifests=npm_manifests,
        npm_manifest_paths=tuple(path.relative_to(root).as_posix() for path in manifests),
        workspace=frozenset(workspace),
        lock_errors=frozenset(errors),
    )


def is_known_crypto(name: str) -> bool:
    return name in KNOWN_CRYPTO or name.startswith(KNOWN_CRYPTO_PREFIXES)


def _is_exact(dependency: Dependency) -> bool:
    pattern = PY_EXACT if dependency.ecosystem == PYPI else NPM_EXACT
    return pattern.match(dependency.spec) is not None


def _all_names(repo: Repo) -> set[str]:
    """Every package name in a lock file or a manifest."""
    return {p.name for p in repo.locked} | {d.name for d in repo.direct}


def check_lock_files(repo: Repo) -> Iterable[Violation]:
    return repo.lock_errors


def check_forbidden(repo: Repo) -> Iterable[Violation]:
    for name in _all_names(repo):
        if name in FORBIDDEN:
            yield "forbidden", name


def check_crypto_unapproved(repo: Repo) -> Iterable[Violation]:
    for name in _all_names(repo):
        if is_known_crypto(name) and name not in APPROVED_CRYPTO and name not in FORBIDDEN:
            yield "crypto-unapproved", name


def check_crypto_unpinned(repo: Repo) -> Iterable[Violation]:
    hashed = {(p.ecosystem, p.name) for p in repo.locked if p.hashed}
    for package in repo.locked:
        if package.name in APPROVED_CRYPTO and not package.hashed:
            yield "crypto-unpinned", package.name
    for dependency in repo.direct:
        if dependency.name not in APPROVED_CRYPTO:
            continue
        if not _is_exact(dependency) or (dependency.ecosystem, dependency.name) not in hashed:
            yield "crypto-unpinned", dependency.name


def check_crypto_unpinned_range(repo: Repo) -> Iterable[Violation]:
    for dependency in repo.direct:
        if dependency.name in EXACT_PIN_REQUIRED and not _is_exact(dependency):
            yield "crypto-unpinned-range", dependency.name


def check_crypto_unsigned_version(repo: Repo) -> Iterable[Violation]:
    for package in repo.locked:
        signed = C6_SIGNED_VERSIONS.get(package.name)
        if signed is not None and package.version != signed:
            yield "crypto-unsigned-version", package.name


def check_sim_in_library(repo: Repo) -> Iterable[Violation]:
    if SIM_PACKAGE in _closure(repo.uv_graph, [LIBRARY_PACKAGE]):
        yield "sim-in-library", SIM_PACKAGE
    for manifest in repo.npm_manifests:
        for group in NPM_ALL_FIELDS:
            for name in manifest.get(group, {}):
                if name == SIM_PACKAGE or name.endswith(f"/{SIM_PACKAGE}"):
                    yield "sim-in-library", name


def check_core_runtime_deps(repo: Repo) -> Iterable[Violation]:
    for manifest in repo.npm_manifests:
        if manifest.get("name") != CORE_PACKAGE:
            continue
        for group in NPM_RUNTIME_FIELDS:
            for name in manifest.get(group, {}):
                if name not in CORE_RUNTIME_ALLOWED:
                    yield "core-runtime-deps", name


def check_web_runtime_closure(repo: Repo) -> Iterable[Violation]:
    for name in repo.library_closures.get(WEB_PACKAGE, frozenset()):
        if name not in WEB_RUNTIME_ALLOWED:
            yield "web-runtime-closure", name


def check_hpke_closure(repo: Repo) -> Iterable[Violation]:
    for library in (LIBRARY_PACKAGE, CORE_PACKAGE, WEB_PACKAGE):
        for name in repo.library_closures.get(library, frozenset()):
            if name in HPKE_CLOSURE_BANNED or name.startswith(HPKE_CLOSURE_BANNED_PREFIXES):
                yield "hpke-closure", name


def check_pyhpke_runtime_deps(repo: Repo) -> Iterable[Violation]:
    for name in repo.uv_runtime_graph.get(PYHPKE, set()) - PYHPKE_RUNTIME_ALLOWED:
        yield "pyhpke-runtime-deps", name


def check_hpke_common_direct(repo: Repo) -> Iterable[Violation]:
    for path, manifest in zip(repo.npm_manifest_paths, repo.npm_manifests, strict=True):
        if any(HPKE_COMMON in manifest.get(group, {}) for group in NPM_ALL_FIELDS):
            yield "hpke-common-direct", path


def check_cbor_x_unused(repo: Repo) -> Iterable[Violation]:
    in_manifest = any(
        CBOR_X in manifest.get(group, {})
        for manifest in repo.npm_manifests
        for group in NPM_ALL_FIELDS
    )
    in_lock = any(p.ecosystem == NPM and p.name == CBOR_X for p in repo.locked)
    if in_manifest or in_lock:
        yield "cbor-x-unused", CBOR_X


class _SpdxParser:
    """Evaluate an SPDX licence expression: true when some alternative uses only allowed ids."""

    def __init__(self, expression: str) -> None:
        self.tokens = re.findall(r"\(|\)|[^\s()]+", expression)
        self.position = 0

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        token = self._peek()
        if token is None:
            raise ValueError("unexpected end of licence expression")
        self.position += 1
        return token

    def parse(self) -> bool:
        result = self._or()
        if self._peek() is not None:
            raise ValueError("trailing tokens in licence expression")
        return result

    def _or(self) -> bool:
        result = self._and()
        while self._peek() == "OR":
            self._take()
            result = self._and() or result
        return result

    def _and(self) -> bool:
        result = self._term()
        while self._peek() == "AND":
            self._take()
            result = self._term() and result
        return result

    def _term(self) -> bool:
        item = self._take()
        if item == "(":
            result = self._or()
            if self._take() != ")":
                raise ValueError("unbalanced licence expression")
            return result
        if self._peek() == "WITH":
            self._take()
            self._take()
            return False
        return item in LICENCES


def licence_allowed(expression: str) -> bool:
    try:
        return _SpdxParser(expression).parse()
    except ValueError:
        return False


NO_LICENCE_STATED = "NOASSERTION"


def _states_a_licence(info: dict[str, Any]) -> bool:
    """True when PyPI metadata carries any licence statement, allowed or not."""
    text = f"{info.get('license_expression') or ''}{info.get('license') or ''}".strip()
    classifiers = [c for c in info.get("classifiers", []) if c.startswith("License ::")]
    return bool(text or classifiers)


def _pypi_licence(info: dict[str, Any]) -> str:
    expression = info.get("license_expression") or info.get("license") or ""
    if expression and licence_allowed(expression):
        return str(expression)
    mapped = [
        CLASSIFIER_LICENCES[c] for c in info.get("classifiers", []) if c in CLASSIFIER_LICENCES
    ]
    return " OR ".join(mapped) or str(expression)


def _pypi_facts(document: dict[str, Any]) -> tuple[str, dt.date | None]:
    uploads = [u["upload_time_iso_8601"] for u in document.get("urls", [])]
    latest = max(uploads, default=None)
    return _pypi_licence(document.get("info", {})), _date(latest)


def _npm_facts(document: dict[str, Any]) -> tuple[str, dt.date | None]:
    latest = document.get("dist-tags", {}).get("latest")
    version = document.get("versions", {}).get(latest, {})
    licence = version.get("license") or document.get("license") or ""
    return str(licence), _date(document.get("time", {}).get(latest))


def _date(timestamp: str | None) -> dt.date | None:
    if not timestamp:
        return None
    return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).date()


def _months_before(day: dt.date, months: int) -> dt.date:
    year, month = divmod(day.year * 12 + day.month - 1 - months, 12)
    month += 1
    return dt.date(year, month, min(day.day, calendar.monthrange(year, month)[1]))


def _project_url(ecosystem: str, name: str) -> str:
    if ecosystem == PYPI:
        return f"https://pypi.org/pypi/{name}/json"
    return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}"


def _version_url(ecosystem: str, name: str, version: str) -> str:
    if ecosystem == PYPI:
        return f"https://pypi.org/pypi/{name}/{urllib.parse.quote(version)}/json"
    return f"{_project_url(ecosystem, name)}/{urllib.parse.quote(version)}"


def _fetch_object(fetch_json: FetchJson, url: str) -> dict[str, Any] | None:
    try:
        document = fetch_json(url)
    except (OSError, ValueError) as error:
        sys.stderr.write(f"registry lookup failed for {url}: {error}\n")
        return None
    if not isinstance(document, dict):
        sys.stderr.write(f"registry document for {url} is not an object\n")
        return None
    return document


def _licence_of(ecosystem: str, name: str, version: str, fetch_json: FetchJson) -> str:
    """Licence of the locked (or exactly pinned) version; the latest release when neither exists."""
    url = _version_url(ecosystem, name, version) if version else _project_url(ecosystem, name)
    document = _fetch_object(fetch_json, url)
    if document is None:
        return ""
    if ecosystem == PYPI:
        info = document.get("info", {})
        if not _states_a_licence(info):
            return NO_LICENCE_STATED
        return _pypi_licence(info)
    if version:
        return str(document.get("license") or "")
    return _npm_facts(document)[0]


def _released(ecosystem: str, name: str, fetch_json: FetchJson) -> dt.date | None:
    document = _fetch_object(fetch_json, _project_url(ecosystem, name))
    if document is None:
        return None
    try:
        return (_pypi_facts(document) if ecosystem == PYPI else _npm_facts(document))[1]
    except (ValueError, KeyError, TypeError):
        return None


def _override(name: str, version: str) -> str:
    override = LICENCE_OVERRIDES.get(f"{name}=={version}")
    if override is not None:
        return override.spdx
    for key in LICENCE_OVERRIDES:
        if key.partition("==")[0] == name:
            sys.stderr.write(f"licence override {key} does not match locked {name}=={version}\n")
    return ""


def _licence_targets(repo: Repo) -> dict[Node, str]:
    """Every locked package plus every direct dependency, with the version to judge."""
    targets: dict[Node, str] = {}
    for dependency in repo.direct:
        exact = PY_EXACT.match(dependency.spec) if dependency.ecosystem == PYPI else None
        version = exact.group(1) if exact else dependency.spec
        if dependency.ecosystem == NPM and not NPM_EXACT.match(version):
            version = ""
        if dependency.ecosystem == PYPI and exact is None:
            version = ""
        targets[(dependency.ecosystem, dependency.name)] = version
    for package in repo.locked:
        targets[(package.ecosystem, package.name)] = package.version
    return {node: v for node, v in targets.items() if node[1] not in repo.workspace}


def _age_exempt(repo: Repo, ecosystem: str, name: str) -> bool:
    exception = AGE_EXCEPTIONS.get(name)
    if exception is None:
        return False
    versions = {p.version for p in repo.locked if (p.ecosystem, p.name) == (ecosystem, name)}
    return versions == {exception.version} and name not in _reached_avoiding(repo, exception.via)


def _reached_avoiding(repo: Repo, avoided: str) -> set[str]:
    """Python runtime nodes reachable from the shipped roots when ``avoided`` is not in the graph."""
    members = {name for name in repo.workspace if name in repo.uv_runtime_graph}
    direct = {d.name for d in repo.direct if d.ecosystem == PYPI and d.shipped}
    roots = (members | direct) - {avoided}
    pruned = {n: edges - {avoided} for n, edges in repo.uv_runtime_graph.items() if n != avoided}
    return roots | _closure(pruned, roots)


def check_registry(repo: Repo, fetch_json: FetchJson, today: dt.date) -> Iterable[Violation]:
    """Licence for every package (D-019: dev tooling included); age for shipped packages only."""
    cutoff = _months_before(today, STALE_MONTHS)
    for (ecosystem, name), version in sorted(_licence_targets(repo).items()):
        licence = _licence_of(ecosystem, name, version, fetch_json)
        if licence == NO_LICENCE_STATED:
            licence = _override(name, version)
        if not licence_allowed(licence):
            yield "licence", name
    for ecosystem, name in sorted(repo.runtime):
        released = _released(ecosystem, name, fetch_json)
        if (released is None or released < cutoff) and not _age_exempt(repo, ecosystem, name):
            yield "stale", name


def evaluate(root: Path, offline: bool, fetch_json: FetchJson, today: dt.date) -> list[Violation]:
    repo = load_repo(root)
    found: set[Violation] = set()
    for check in (
        check_lock_files,
        check_forbidden,
        check_crypto_unapproved,
        check_crypto_unpinned,
        check_crypto_unpinned_range,
        check_crypto_unsigned_version,
        check_sim_in_library,
        check_core_runtime_deps,
        check_web_runtime_closure,
        check_hpke_closure,
        check_pyhpke_runtime_deps,
        check_hpke_common_direct,
        check_cbor_x_unused,
    ):
        found.update(check(repo))
    if not offline:
        found.update(check_registry(repo, fetch_json, today))
    return sorted(found, key=lambda v: (RULE_ORDER.index(v[0]), v[1]))


def main(argv: list[str] | None = None, fetch_json: FetchJson | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    args = parser.parse_args(argv)
    violations = evaluate(args.root, args.offline, fetch_json or fetch_registry_json, args.today)
    for rule, package in violations:
        sys.stdout.write(f"VIOLATION {rule} {package}\n")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
