"""INC-1 Wave 4 acceptance tests derived from QA defects D-01, D-03, D-04 and the vectors guard.

Expected on trunk before the fixes: every test here FAILS. Never writes to the real spec/vectors.
"""

import os
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from acc_support import AUDIENCE, IMAGE_DIGEST, RunningSim
from teecustody_sim.cli import main

Cli = Callable[..., tuple[int, str, str]]
SERVE = [
    "serve",
    "--audience",
    AUDIENCE,
    "--image-reference",
    "localhost/x:1",
    "--image-digest",
    IMAGE_DIGEST,
]


@pytest.fixture
def cli(capsys: pytest.CaptureFixture[str]) -> Cli:
    def run(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


def _serve_proc(workdir: Path, *extra: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "teecustody_sim",
            *SERVE,
            "--state-dir",
            str(workdir / "st"),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return proc.returncode, proc.stderr


# ---- D-01 specific codes instead of INTERNAL --------------------------------------------------


def test_D01_serve_with_directory_at_socket_path_is_a_validation_error(workdir: Path) -> None:
    # Given a directory where the launcher socket should be
    sock = workdir / "adir"
    sock.mkdir()
    # When serving
    code, err = _serve_proc(workdir, "--socket", str(sock))
    # Then a specific validation code, not INTERNAL
    assert (code, err) == (2, "INVALID_PATH\n")


def test_D01_serve_with_unbindable_issuer_host_is_bind_failed(workdir: Path) -> None:
    # Given an issuer host that cannot be bound on this machine
    code, err = _serve_proc(
        workdir,
        "--socket",
        str(workdir / "s.sock"),
        "--issuer-host",
        "192.0.2.1",
        "--allow-non-loopback",
    )
    # Then BIND_FAILED (API.md section C), exit 2, one stderr line after the allowed warning
    assert code == 2
    assert err.splitlines()[-1] == "BIND_FAILED"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_D01_vectors_into_unwritable_directory_is_invalid_path(cli: Cli, workdir: Path) -> None:
    # Given an output directory that cannot be written
    out = workdir / "ro"
    out.mkdir()
    out.chmod(0o500)
    try:
        code, _, err = cli("vectors", "--state-dir", str(workdir / "st"), "--out", str(out))
    finally:
        out.chmod(0o700)
    # Then INVALID_PATH, exit 2
    assert (code, err) == (2, "INVALID_PATH\n")


# ---- D-04 empty env name ---------------------------------------------------------------------


@pytest.mark.parametrize("pair", ["=x", "=", "=a=b"])
def test_D04_serve_rejects_empty_env_name(workdir: Path, pair: str) -> None:
    # When serving with an environment entry that has no name
    code, err = _serve_proc(workdir, "--socket", str(workdir / "s.sock"), "--env", pair)
    # Then rejected like a missing '=' and no state is created
    assert (code, err) == (2, "INVALID_ARGUMENT\n")
    assert not (workdir / "s.sock").exists()


# ---- D-03 burst against the launcher socket -------------------------------------------------


def test_D03_burst_of_100_connections_each_gets_a_response(running_sim: RunningSim) -> None:
    # Given a running simulator and 100 simultaneous token requests
    import json

    body = json.dumps({"audience": AUDIENCE, "token_type": "OIDC", "nonces": ["00" * 32]}).encode()
    req = (
        b"POST /v1/token HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    )
    results: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(100)

    def one() -> None:
        outcome = "?"
        try:
            barrier.wait(timeout=20)
            with socket.socket(socket.AF_UNIX) as c:
                c.settimeout(15)
                c.connect(str(running_sim.config.socket_path))
                c.sendall(req)
                data = b""
                while chunk := c.recv(65536):
                    data += chunk
            outcome = data.split(b"\r\n", 1)[0].decode(errors="replace")
        except Exception as exc:  # noqa: BLE001
            outcome = type(exc).__name__
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=one) for _ in range(100)]
    [t.start() for t in threads]
    [t.join(timeout=30) for t in threads]
    # Then every connection got a complete HTTP answer: success or an explicit refusal, no drops
    assert len(results) == 100
    bad = [r for r in results if not r.startswith("HTTP/1.")]
    assert bad == [], sorted(set(bad))
    assert sum(r.startswith("HTTP/1.0 200") or r.startswith("HTTP/1.1 200") for r in results) >= 1


# ---- vectors overwrite guard -------------------------------------------------------------------


def _tree(root: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()
    }


def test_vectors_refuses_to_overwrite_existing_suite_without_force(cli: Cli, workdir: Path) -> None:
    # Given an output directory holding a previously written suite
    out = workdir / "v"
    code, _, err = cli("vectors", "--state-dir", str(workdir / "st"), "--out", str(out))
    assert code == 0, err
    before = _tree(out)
    assert before
    # When vectors is run again without --force
    code, stdout, err = cli("vectors", "--state-dir", str(workdir / "st"), "--out", str(out))
    # Then it refuses and every file is byte-identical
    assert (code, stdout, err) == (2, "", "OUTPUT_EXISTS\n")
    assert _tree(out) == before


def test_vectors_with_force_regenerates(cli: Cli, workdir: Path) -> None:
    # Given an existing suite
    out = workdir / "v"
    assert cli("vectors", "--state-dir", str(workdir / "st"), "--out", str(out))[0] == 0
    before = _tree(out)
    # When run with --force
    code, stdout, err = cli(
        "vectors", "--state-dir", str(workdir / "st"), "--out", str(out), "--force"
    )
    # Then it succeeds, lists all three paths (attestation, corpus, channel: INC-2-API A-4), and
    # the suite (ephemeral keys) is regenerated
    assert code == 0, err
    assert stdout.count("\n") == 3
    after = _tree(out)
    assert set(after) == set(before)
    assert after["attestation/suite.cbor"] != before["attestation/suite.cbor"]
