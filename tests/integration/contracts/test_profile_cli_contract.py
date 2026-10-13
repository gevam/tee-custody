"""Contract: `teecustody-profile check-discovery` (T-35; INC-2-API §16.5, §16.6; ADR 0012; SR-1).

Tech Lead, INC-2 D-043 pass. Process-level boundary consumed by T-31 (N3) and the scheduled
`discovery-binding` CI job. Expected red until T-21 (`build_trust_profile(jwks_uri=...)`, simulator
`jwks_uri`) and T-35 (the `build:cli` script and `dist/profile/bin.js`) have merged.

Invocation pinned by API-TL TL-10: `pnpm --filter @teecustody/web run build:cli`, then
`node packages/teecustody-web/dist/profile/bin.js check-discovery ...`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from collections.abc import Iterator
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tc_contract_support import (
    ARGS,
    AUDIENCE,
    ENV,
    IMAGE_DIGEST,
    IMAGE_REFERENCE,
    RunningSimulator,
)

from teecustody_sim import LaunchConfig, SimKeys, build_trust_profile

REPO = Path(__file__).resolve().parents[3]
BIN = REPO / "packages" / "teecustody-web" / "dist" / "profile" / "bin.js"
DISCOVERY_PATH = "/.well-known/openid-configuration"
BUILD_ARGV = ["pnpm", "--filter", "@teecustody/web", "run", "build:cli"]  # pnpm from PATH
NODE = ["node"]  # node from PATH, as in every dev and CI shell
OK_LINE = re.compile(r"^ok issuer=(\S+) jwks_uri=(\S+) keys=([1-9][0-9]*)$")


@pytest.fixture(scope="module")
def cli() -> Path:
    built = subprocess.run(  # noqa: S603 - fixed argv
        BUILD_ARGV,
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert built.returncode == 0, "build:cli failed"
    assert BIN.is_file()
    return BIN


def _run(
    cli: Path, *args: str, env_extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "NODE_TLS_REJECT_UNAUTHORIZED"}
    env.update(env_extra or {})
    return subprocess.run(  # noqa: S603 - fixed argv; args are test literals
        [*NODE, str(cli), "check-discovery", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )


def _write_profile(tmp_path: Path, jwks_uri: str) -> Path:
    launch = LaunchConfig(
        image_reference=IMAGE_REFERENCE, image_digest=IMAGE_DIGEST, args=ARGS, env=ENV
    )
    profile = build_trust_profile(
        jwks_uri=jwks_uri,
        expected_audience=AUDIENCE,
        launch=launch,
        signers=SimKeys.generate(1).signers,
        signers_required=1,
    )
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile))
    return path


class _Fixture:
    """A loopback origin serving a discovery document and a one-key JWKS, optionally with ACAO."""

    def __init__(self, discovery_jwks_suffix: str) -> None:
        self.discovery_jwks_suffix = discovery_jwks_suffix
        self.issuer = ""
        handler = self._handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == DISCOVERY_PATH:
                    jwks_uri = fixture.origin + "/jwks" + fixture.discovery_jwks_suffix
                    body: object = {"issuer": fixture.issuer, "jwks_uri": jwks_uri}
                elif self.path == "/jwks":
                    key = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1", "n": "AQAB"}
                    body = {"keys": [{**key, "e": "AQAB"}]}
                else:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                data = json.dumps(body).encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        return Handler

    def __enter__(self) -> _Fixture:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def mismatch_origin() -> Iterator[_Fixture]:
    with _Fixture(discovery_jwks_suffix="/") as fixture:
        yield fixture


def test_simulator_binding_with_cors_probe_succeeds(
    cli: Path, running_simulator: RunningSimulator, tmp_path: Path
) -> None:
    simulator = running_simulator.simulator
    profile = _write_profile(tmp_path, simulator.jwks_uri)
    result = _run(
        cli,
        "--profile",
        str(profile),
        "--discovery-url",
        simulator.discovery_url,
        "--probe-cors",
        "http://127.0.0.1:1",
    )
    assert result.returncode == 0
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    head, _, probe = lines[0].partition(" jwks_acao=")
    match = OK_LINE.fullmatch(head)
    assert match is not None
    assert match.group(2) == simulator.jwks_uri
    jwks_acao, _, discovery_acao = probe.partition(" discovery_acao=")
    assert jwks_acao in {"*", "http://127.0.0.1:1"}  # §16.5: `*` or the probe origin
    assert discovery_acao == "absent"  # Google parity (CI-2-1, V-2.7)


def test_discovery_jwks_uri_with_trailing_slash_is_a_mismatch(
    cli: Path, mismatch_origin: _Fixture, tmp_path: Path
) -> None:
    profile_path = _write_profile(tmp_path, mismatch_origin.origin + "/jwks")
    mismatch_origin.issuer = json.loads(profile_path.read_text())["issuer"]
    result = _run(
        cli,
        "--profile",
        str(profile_path),
        "--discovery-url",
        mismatch_origin.origin + DISCOVERY_PATH,
    )
    assert (result.returncode, result.stdout, result.stderr) == (1, "", "JWKS_URI_MISMATCH\n")


def test_insecure_tls_environment_exits_2_before_any_network(cli: Path, tmp_path: Path) -> None:
    profile = _write_profile(tmp_path, "http://127.0.0.1:9/jwks")
    result = _run(
        cli,
        "--profile",
        str(profile),
        "--discovery-url",
        "http://127.0.0.1:9" + DISCOVERY_PATH,
        env_extra={"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
    )
    assert (result.returncode, result.stdout, result.stderr) == (
        2,
        "",
        "INSECURE_TLS_ENVIRONMENT\n",
    )


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("--profile",),
        ("--skip-verification",),
        ("--offline",),
        ("--timeout-ms", "0"),
        ("--timeout-ms", "60001"),
    ],
)
def test_bad_arguments_exit_2(cli: Path, args: tuple[str, ...]) -> None:
    result = _run(cli, *args)
    assert (result.returncode, result.stdout, result.stderr) == (2, "", "INVALID_ARGUMENT\n")


def test_v1_profile_is_invalid(cli: Path, tmp_path: Path) -> None:
    path = tmp_path / "v1.json"
    path.write_text(json.dumps({"profile_version": 1}))
    result = _run(
        cli, "--profile", str(path), "--discovery-url", "http://127.0.0.1:9" + DISCOVERY_PATH
    )
    assert (result.returncode, result.stdout, result.stderr) == (2, "", "INVALID_PROFILE\n")


def test_development_discovery_on_another_origin_is_invalid(cli: Path, tmp_path: Path) -> None:
    profile = _write_profile(tmp_path, "http://127.0.0.1:9/jwks")
    result = _run(
        cli, "--profile", str(profile), "--discovery-url", "http://127.0.0.1:10" + DISCOVERY_PATH
    )
    assert (result.returncode, result.stdout, result.stderr) == (2, "", "INVALID_ARGUMENT\n")
