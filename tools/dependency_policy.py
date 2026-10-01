"""Dependency policy check (SR-9, NFR-6; framework.yaml security.dependency_policy, D-019).

Reads uv.lock, pnpm-lock.yaml and the Python and npm manifests at the repository root and under
packages/, prints one ``VIOLATION <rule> <package>`` line per violation and exits 1 if there is any.
"""

import argparse
import calendar
import datetime as dt
import json
import re
import sys
import tomllib
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN = frozenset(
    {"pycrypto", "pyaes", "tinyec", "crypto-js", "node-forge", "elliptic", "sjcl"},
)
SIM_PACKAGE = "teecustody-sim"
LIBRARY_PACKAGE = "teecustody"
CORE_PACKAGE = "@teecustody/core"
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
    },
)
KNOWN_CRYPTO_PREFIXES = ("@noble/",)
APPROVED_CRYPTO = frozenset({"cryptography", "pyhpke", "tink", "cbor2", "@hpke/core", "cbor-x"})
CORE_RUNTIME_ALLOWED = frozenset({"@hpke/core"})

LICENCES = frozenset(
    {
        "MIT",
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

RULE_ORDER = (
    "forbidden",
    "crypto-unapproved",
    "crypto-unpinned",
    "sim-in-library",
    "core-runtime-deps",
    "cbor-x-unused",
    "licence",
    "stale",
)

PYPI = "pypi"
NPM = "npm"
NPM_RUNTIME_FIELDS = ("dependencies", "peerDependencies", "optionalDependencies")
NPM_ALL_FIELDS = (*NPM_RUNTIME_FIELDS, "devDependencies")
PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)")
PY_EXACT = re.compile(r"^==\s*[A-Za-z0-9.+!_-]+$")
NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PNPM_KEY = re.compile(r"^  (['\"]?)(?P<key>[^'\"\s].*?)\1:\s*$")
PNPM_INTEGRITY = re.compile(r"integrity:\s*sha(?:256|384|512)-")

FetchJson = Callable[[str], object]
Violation = tuple[str, str]


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
    ecosystem: str
    hashed: bool


@dataclass(frozen=True)
class Repo:
    """Everything the rules read from one repository tree."""

    locked: tuple[Locked, ...]
    direct: tuple[Dependency, ...]
    uv_graph: dict[str, frozenset[str]]
    npm_manifests: tuple[dict[str, Any], ...]
    workspace: frozenset[str]


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


def _parse_uv_lock(path: Path) -> tuple[list[Locked], dict[str, frozenset[str]], set[str]]:
    data = _read_toml(path)
    locked: list[Locked] = []
    graph: dict[str, frozenset[str]] = {}
    for package in data.get("package", []):
        name = normalise_python(package["name"])
        hashes = [package.get("sdist", {}).get("hash")]
        hashes += [wheel.get("hash") for wheel in package.get("wheels", [])]
        locked.append(Locked(name, PYPI, any(hashes)))
        edges = list(package.get("dependencies", []))
        for group_key in ("optional-dependencies", "dev-dependencies"):
            for group in package.get(group_key, {}).values():
                edges.extend(group)
        graph[name] = frozenset(normalise_python(edge["name"]) for edge in edges)
    members = {normalise_python(m) for m in data.get("manifest", {}).get("members", [])}
    return locked, graph, members


def _parse_pnpm_lock(path: Path) -> list[Locked]:
    if not path.is_file():
        return []
    locked: list[Locked] = []
    section = ""
    name: str | None = None
    hashed = False
    for line in [*path.read_text(encoding="utf-8").splitlines(), "end:"]:
        key = PNPM_KEY.match(line)
        if (line and not line[0].isspace()) or key:
            if name is not None:
                locked.append(Locked(name, NPM, hashed))
            name, hashed = None, False
        if line and not line[0].isspace():
            section = line.rstrip(":").strip()
        elif section == "packages" and key:
            spec = key.group("key").split("(", 1)[0]
            name = spec[: spec.rindex("@")] if spec.rfind("@") > 0 else spec
        elif name is not None and PNPM_INTEGRITY.search(line):
            hashed = True
    return locked


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
        for field in NPM_ALL_FIELDS:
            for name, spec in manifest.get(field, {}).items():
                direct.append(Dependency(name, str(spec), NPM, field != "devDependencies"))
    return direct


def load_repo(root: Path) -> Repo:
    uv_locked, uv_graph, members = _parse_uv_lock(root / "uv.lock")
    pyprojects = [root / "pyproject.toml", *sorted(root.glob("packages/*/pyproject.toml"))]
    package_jsons = [root / "package.json", *sorted(root.glob("packages/*/package.json"))]
    npm_manifests = tuple(_read_json(path) for path in package_jsons if path.is_file())
    workspace = members | {str(m["name"]) for m in npm_manifests if "name" in m}
    for path in pyprojects:
        name = _read_toml(path).get("project", {}).get("name")
        if name:
            workspace.add(normalise_python(name))
    return Repo(
        locked=tuple(uv_locked + _parse_pnpm_lock(root / "pnpm-lock.yaml")),
        direct=tuple(_python_direct(pyprojects) + _npm_direct(npm_manifests)),
        uv_graph=uv_graph,
        npm_manifests=npm_manifests,
        workspace=frozenset(workspace),
    )


def _is_known_crypto(name: str) -> bool:
    return name in KNOWN_CRYPTO or name.startswith(KNOWN_CRYPTO_PREFIXES)


def _is_exact(dependency: Dependency) -> bool:
    pattern = PY_EXACT if dependency.ecosystem == PYPI else NPM_EXACT
    return pattern.match(dependency.spec) is not None


def check_forbidden(repo: Repo) -> Iterable[Violation]:
    for package in repo.locked:
        if package.name in FORBIDDEN:
            yield "forbidden", package.name


def check_crypto_unapproved(repo: Repo) -> Iterable[Violation]:
    for package in repo.locked:
        name = package.name
        if _is_known_crypto(name) and name not in APPROVED_CRYPTO and name not in FORBIDDEN:
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


def _closure(graph: dict[str, frozenset[str]], start: str) -> set[str]:
    seen: set[str] = set()
    pending = [start]
    while pending:
        for edge in graph.get(pending.pop(), frozenset()):
            if edge not in seen:
                seen.add(edge)
                pending.append(edge)
    return seen


def check_sim_in_library(repo: Repo) -> Iterable[Violation]:
    if SIM_PACKAGE in _closure(repo.uv_graph, LIBRARY_PACKAGE):
        yield "sim-in-library", SIM_PACKAGE
    for manifest in repo.npm_manifests:
        for field in NPM_ALL_FIELDS:
            for name in manifest.get(field, {}):
                if name == SIM_PACKAGE or name.endswith(f"/{SIM_PACKAGE}"):
                    yield "sim-in-library", name


def check_core_runtime_deps(repo: Repo) -> Iterable[Violation]:
    for manifest in repo.npm_manifests:
        if manifest.get("name") != CORE_PACKAGE:
            continue
        for field in NPM_RUNTIME_FIELDS:
            for name in manifest.get(field, {}):
                if name not in CORE_RUNTIME_ALLOWED:
                    yield "core-runtime-deps", name


def check_cbor_x_unused(repo: Repo) -> Iterable[Violation]:
    in_manifest = any(
        CBOR_X in manifest.get(field, {})
        for manifest in repo.npm_manifests
        for field in NPM_ALL_FIELDS
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


def _registry_url(dependency: Dependency) -> str:
    if dependency.ecosystem == PYPI:
        return f"https://pypi.org/pypi/{dependency.name}/json"
    return f"https://registry.npmjs.org/{urllib.parse.quote(dependency.name, safe='@')}"


def check_registry(repo: Repo, fetch_json: FetchJson, today: dt.date) -> Iterable[Violation]:
    cutoff = _months_before(today, STALE_MONTHS)
    shipped: dict[tuple[str, str], bool] = {}
    for dependency in repo.direct:
        if dependency.name in repo.workspace:
            continue
        key = (dependency.ecosystem, dependency.name)
        shipped[key] = shipped.get(key, False) or dependency.shipped
    for (ecosystem, name), is_shipped in sorted(shipped.items()):
        dependency = Dependency(name, "", ecosystem, is_shipped)
        try:
            document = fetch_json(_registry_url(dependency))
            if not isinstance(document, dict):
                raise ValueError("registry document is not an object")
            facts = _pypi_facts(document) if ecosystem == PYPI else _npm_facts(document)
        except (OSError, ValueError, KeyError, TypeError) as error:
            sys.stderr.write(f"registry lookup failed for {name}: {error}\n")
            facts = ("", None)
        licence, released = facts
        if not licence_allowed(licence):
            yield "licence", name
        if is_shipped and (released is None or released < cutoff):
            yield "stale", name


def evaluate(root: Path, offline: bool, fetch_json: FetchJson, today: dt.date) -> list[Violation]:
    repo = load_repo(root)
    found: set[Violation] = set()
    for check in (
        check_forbidden,
        check_crypto_unapproved,
        check_crypto_unpinned,
        check_sim_in_library,
        check_core_runtime_deps,
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
