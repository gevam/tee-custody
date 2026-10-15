"""End-to-end channel harness (INC-2-API §9.4; API-TL TL-8; FR-4, FR-5, NFR-2, SR-11).

    uv run python tests/e2e/channel_harness.py [--cors-origin ORIGIN]...

One process on loopback: the simulator (issuer and launcher socket), the workload `RunLoop` in a
thread over an `InMemoryQueue`, and the reference gateway under uvicorn. The workload has no
listener; only the gateway and the simulator bind sockets (D-003). Once the first bundle is
listed, it prints exactly one stdout line `gateway=<origin> issuer=<origin> profile=<path>`. The
profile's directory also holds `fixture.json` (mode 0600): a per-run client share for tests only,
never committed and never printed. SIGTERM or SIGINT stops everything, removes the temporary
directory and exits 0.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import Final

import fastapi
import uvicorn
from notes_gateway import GatewayLimits, create_app

from teecustody.attest import ConfidentialSpaceLauncher
from teecustody.runtime import RunLoop
from teecustody_sim import (
    DEFAULT_TOKEN_MAX_AGE_S,
    LaunchConfig,
    NamedCase,
    Simulator,
    SimulatorConfig,
    TokenMinter,
    build_trust_profile,
)
from teecustody_sim.backends import InMemoryAuditSink, InMemoryQueue

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
AUDIENCE: Final = "https://e2e.teecustody.test/tee"
TOKEN_TYPE: Final = "OIDC"
LAUNCH: Final = LaunchConfig(
    image_reference="localhost/teecustody-e2e:1",
    image_digest="sha256:" + "e2" * 32,
    args=("/app/workload",),
    env=(),
)
READY_TIMEOUT_S: Final = 30.0
STOP_TIMEOUT_S: Final = 5.0
POLL_S: Final = 0.05
FIXTURE_MODE: Final = 0o600


def server_config(app: fastapi.FastAPI) -> uvicorn.Config:
    """The gateway's uvicorn configuration (A3): no proxy headers, server header or access log."""
    return uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        log_level="warning",
    )


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="channel_harness")
    parser.add_argument("--cors-origin", action="append", default=[])
    return parser.parse_args(argv)


def _write_private(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FIXTURE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


class _Harness:
    def __init__(self, temp_dir: Path, cors_origins: tuple[str, ...]) -> None:
        self.temp_dir = temp_dir
        self.cors_origins = cors_origins
        self.shutdown = threading.Event()
        self.stop = threading.Event()
        self.simulator: Simulator | None = None
        self.server: uvicorn.Server | None = None
        self.threads: list[threading.Thread] = []
        self.failure: BaseException | None = None

    def request_shutdown(self, signum: int, frame: FrameType | None) -> None:
        self.shutdown.set()

    def run(self) -> int:
        sim_config = SimulatorConfig(
            state_dir=self.temp_dir / "state",
            socket_path=self.temp_dir / "l.sock",
            token_file_path=self.temp_dir / "token",
            launch=LAUNCH,
            audience=AUDIENCE,
            issuer_port=0,
        )
        self.simulator = simulator = Simulator(sim_config)
        simulator.start()
        profile = build_trust_profile(
            jwks_uri=simulator.jwks_uri,
            expected_audience=AUDIENCE,
            launch=LAUNCH,
            signers=simulator.keys.signers,
            signers_required=sim_config.signers_required,
        )
        profile_path = self.temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")
        client_id = os.urandom(16).hex()
        client_share = os.urandom(32)
        attacker_token = TokenMinter(
            simulator.keys,
            LAUNCH,
            ttl_s=sim_config.token_ttl_s,
            token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S,
        ).mint(AUDIENCE, [os.urandom(32).hex()], int(time.time()), NamedCase("jwks_other_path"))
        fixture = {
            "client_id": client_id,
            "cs": client_share.hex(),
            "key_id": os.urandom(16).hex(),
            "epoch": 0,
            "discovery_url": simulator.discovery_url,
            "attacker_jwks_url": simulator.attacker_jwks_uri,
            "attacker_token": attacker_token,
        }
        _write_private(self.temp_dir / "fixture.json", json.dumps(fixture))

        from tests.support.channel_doubles import EchoHandler, StaticShareOpener

        queue = InMemoryQueue()
        loop = RunLoop(
            launcher=ConfidentialSpaceLauncher(
                str(sim_config.socket_path), timeout_s=5.0, max_response_bytes=65536
            ),
            queue=queue,
            audit_sink=InMemoryAuditSink(),
            opener=StaticShareOpener({client_id: client_share}),
            handler=EchoHandler(),
            audience=AUDIENCE,
            token_type=TOKEN_TYPE,
        )
        self._spawn(lambda: loop.run(self.stop))
        app = create_app(queue, limits=GatewayLimits(cors_origins=self.cors_origins))
        self.server = server = uvicorn.Server(server_config(app))
        self._spawn(server.run)

        if not self._await(
            lambda: (
                server.started
                and any(b.instance_id == loop.instance_id for b in queue.list_bundles(16))
            )
        ):
            return 1
        host, port = server.servers[0].sockets[0].getsockname()[:2]
        gateway = f"http://{host}:{port}"
        sys.stdout.write(
            f"gateway={gateway} issuer={simulator.issuer_origin} profile={profile_path}\n"
        )
        sys.stdout.flush()
        while not self.shutdown.wait(POLL_S):
            if not self._alive():
                return 1
        return 0

    def _spawn(self, target: Callable[[], object]) -> None:
        def guarded() -> None:
            try:
                target()
            except BaseException as error:  # noqa: BLE001 - reported as the exit status
                self.failure = error

        thread = threading.Thread(target=guarded, daemon=True)
        self.threads.append(thread)
        thread.start()

    def _alive(self) -> bool:
        return self.failure is None and all(thread.is_alive() for thread in self.threads)

    def _await(self, ready: Callable[[], bool]) -> bool:
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline and not self.shutdown.is_set():
            if not self._alive():
                return False
            if ready():
                return True
            time.sleep(POLL_S)
        return False

    def close(self) -> None:
        self.stop.set()
        if self.server is not None:
            self.server.should_exit = True
        for thread in self.threads:
            thread.join(STOP_TIMEOUT_S)
        if self.simulator is not None:
            self.simulator.stop()


def main(argv: Sequence[str] | None = None) -> int:
    options = _parse(argv)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    temp_dir = Path(tempfile.mkdtemp(prefix="tc-e2e-"))
    harness = _Harness(temp_dir, tuple(options.cors_origin))
    previous = {
        signum: signal.signal(signum, harness.request_shutdown)
        for signum in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        code = harness.run()
    finally:
        harness.close()
        shutil.rmtree(temp_dir, ignore_errors=True)
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    if harness.failure is not None:
        sys.stderr.write(f"harness: {type(harness.failure).__name__}\n")
        return 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
