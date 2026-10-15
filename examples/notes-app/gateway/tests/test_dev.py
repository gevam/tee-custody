"""T-31 criterion 7: `python -m notes_gateway.dev` (API-TL TL-5; INC-2-API §6, A3).

Every test that starts a server has a bounded wait and stops it on teardown.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn

from notes_gateway import dev

READY_TIMEOUT_S = 30.0
STOP_TIMEOUT_S = 10.0
GATEWAY_LINE = re.compile(r"^gateway=(http://127\.0\.0\.1:(\d+))$")


def _get(url: str) -> tuple[int, Any]:
    assert url.startswith("http://127.0.0.1:")
    with urllib.request.urlopen(url, timeout=STOP_TIMEOUT_S) as response:  # noqa: S310 - loopback
        return response.status, json.loads(response.read())


@pytest.fixture
def dev_process() -> Iterator[subprocess.Popen[str]]:
    proc = subprocess.Popen(
        [sys.executable, "-m", "notes_gateway.dev", "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(STOP_TIMEOUT_S)
        assert proc.stdout is not None
        proc.stdout.close()


def _first_line(proc: subprocess.Popen[str]) -> str:
    lines: list[str] = []
    assert proc.stdout is not None
    stdout = proc.stdout
    reader = threading.Thread(target=lambda: lines.append(stdout.readline()), daemon=True)
    reader.start()
    reader.join(READY_TIMEOUT_S)
    assert lines, "no output within 30 s"
    return lines[0].rstrip("\n")


def test_module_prints_origin_serves_empty_bundles_and_exits_zero_on_sigterm(
    dev_process: subprocess.Popen[str],
) -> None:
    match = GATEWAY_LINE.fullmatch(_first_line(dev_process))
    assert match is not None
    assert _get(f"{match[1]}/bundles") == (200, {"bundles": []})
    dev_process.send_signal(signal.SIGTERM)
    assert dev_process.wait(STOP_TIMEOUT_S) == 0


class _Recorder:
    """Records every uvicorn Config (with its keyword arguments) and Server that `main` builds."""

    def __init__(self) -> None:
        self.config_kwargs: list[dict[str, Any]] = []
        self.configs: list[uvicorn.Config] = []
        self.servers: list[uvicorn.Server] = []


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    record = _Recorder()
    real_config, real_server = uvicorn.Config, uvicorn.Server

    class RecordingConfig(real_config):  # type: ignore[valid-type,misc]
        def __init__(self, app: Any, **kwargs: Any) -> None:
            record.config_kwargs.append(kwargs)
            record.configs.append(self)
            super().__init__(app, **kwargs)

    class RecordingServer(real_server):  # type: ignore[valid-type,misc]
        def __init__(self, config: uvicorn.Config) -> None:
            record.servers.append(self)
            super().__init__(config)

    monkeypatch.setattr(uvicorn, "Config", RecordingConfig)
    monkeypatch.setattr(uvicorn, "Server", RecordingServer)
    return record


def _terminate_when_serving(record: _Recorder, seen: list[tuple[int, Any]]) -> threading.Thread:
    """Once the recorded server is up: GET /bundles, then SIGTERM this process (main's handler)."""

    def run() -> None:
        deadline = time.monotonic() + READY_TIMEOUT_S
        while time.monotonic() < deadline:
            if record.servers and record.servers[0].started:
                port = record.servers[0].servers[0].sockets[0].getsockname()[1]
                seen.append(_get(f"http://127.0.0.1:{port}/bundles"))
                os.kill(os.getpid(), signal.SIGTERM)
                return
            time.sleep(0.01)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_main_runs_uvicorn_without_proxy_headers_server_header_or_access_log(
    recorder: _Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[tuple[int, Any]] = []
    helper = _terminate_when_serving(recorder, seen)
    assert dev.main(["--port", "0"]) == 0
    helper.join(STOP_TIMEOUT_S)
    assert seen == [(200, {"bundles": []})]
    [config] = recorder.configs
    assert config.proxy_headers is False
    assert config.server_header is False
    assert config.access_log is False
    assert "forwarded_allow_ips" not in recorder.config_kwargs[0]
    assert (config.host, config.port) == ("127.0.0.1", 0)
    match = GATEWAY_LINE.fullmatch(capsys.readouterr().out.rstrip("\n"))
    assert match is not None
