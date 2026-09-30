"""T-01: repository policies that lint and packaging enforce mechanically.

SR-3 (single CBOR decode entry point), NFR-2 (no inbound listener) and NFR-6 (the simulator is
never imported by `teecustody`) are ruff TID251 bans; see packages/*/ruff.toml.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PY_SRC = "packages/teecustody-py/src/teecustody"
SIM_SRC = "packages/teecustody-sim/src/teecustody_sim"


def _ruff_stdin(filename: str, source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv: this interpreter running ruff
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--output-format=concise",
            "--stdin-filename",
            filename,
            "-",
        ],
        input=source,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


# (import statement, a use of the imported name so the snippet is otherwise lint-clean)
CBOR2_IMPORTS = [("import cbor2", "cbor2.dumps"), ("from cbor2 import loads", "loads")]
LISTENER_IMPORTS = [
    ("import http.server", "http.server.HTTPServer"),
    ("from http.server import HTTPServer", "HTTPServer"),
    ("import socketserver", "socketserver.TCPServer"),
    ("from socketserver import TCPServer", "TCPServer"),
]
SIM_IMPORTS = [
    ("import teecustody_sim", "teecustody_sim.SIM_ISSUER"),
    ("from teecustody_sim import SIM_ISSUER", "SIM_ISSUER"),
    ("from teecustody_sim.constants import SIM_ISSUER", "SIM_ISSUER"),
]


def _snippet(statement: str, use: str) -> str:
    return f"{statement}\n\nVALUE = {use}\n"


@pytest.mark.parametrize(("statement", "use"), CBOR2_IMPORTS + LISTENER_IMPORTS + SIM_IMPORTS)
def test_teecustody_source_rejects_banned_imports(statement: str, use: str) -> None:
    result = _ruff_stdin(f"{PY_SRC}/attest/x.py", _snippet(statement, use))
    assert result.returncode != 0
    assert "TID251" in result.stdout


@pytest.mark.parametrize(("statement", "use"), CBOR2_IMPORTS)
def test_wire_cbor_module_may_import_cbor2(statement: str, use: str) -> None:
    result = _ruff_stdin(f"{PY_SRC}/wire/cbor.py", _snippet(statement, use))
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(("statement", "use"), CBOR2_IMPORTS + LISTENER_IMPORTS + SIM_IMPORTS)
def test_teecustody_tests_are_exempt_from_import_bans(statement: str, use: str) -> None:
    result = _ruff_stdin("packages/teecustody-py/tests/test_x.py", _snippet(statement, use))
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(("statement", "use"), CBOR2_IMPORTS)
def test_simulator_source_rejects_cbor2(statement: str, use: str) -> None:
    result = _ruff_stdin(f"{SIM_SRC}/x.py", _snippet(statement, use))
    assert result.returncode != 0
    assert "TID251" in result.stdout


@pytest.mark.parametrize(("statement", "use"), LISTENER_IMPORTS)
def test_simulator_source_may_serve_loopback_listeners(statement: str, use: str) -> None:
    result = _ruff_stdin(f"{SIM_SRC}/x.py", _snippet(statement, use))
    assert result.returncode == 0, result.stdout
