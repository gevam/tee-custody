"""T-31 criterion 7: `python -m notes_gateway.dev` (API-TL TL-5; INC-2-API §6, A3).

Every test that starts a server has a bounded wait and stops it on teardown.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import re
import runpy
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn

from notes_gateway import GatewayLimits, create_app, dev

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


@pytest.fixture
def sigterm_guard() -> Iterator[None]:
    """A harmless SIGTERM handler while the test runs: a SIGTERM that lands after `main` has
    restored its predecessor can never kill pytest."""
    previous = signal.signal(signal.SIGTERM, lambda signum, frame: None)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _terminate_when_serving(record: _Recorder, seen: list[tuple[int, Any]]) -> threading.Thread:
    """Once the recorded server is up, GET /bundles. Whatever happens (a failed GET, the deadline),
    SIGTERM this process afterwards, so `main` always returns and a broken gateway fails fast."""

    def run() -> None:
        try:
            deadline = time.monotonic() + READY_TIMEOUT_S
            while time.monotonic() < deadline:
                if record.servers and record.servers[0].started:
                    port = record.servers[0].servers[0].sockets[0].getsockname()[1]
                    seen.append(_get(f"http://127.0.0.1:{port}/bundles"))
                    return
                time.sleep(0.01)
        except Exception as error:  # noqa: BLE001 - recorded, so the test's assertion fails
            seen.append((0, type(error).__name__))
        finally:
            os.kill(os.getpid(), signal.SIGTERM)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@pytest.mark.usefixtures("sigterm_guard")
def test_main_runs_uvicorn_without_proxy_headers_server_header_or_access_log(
    recorder: _Recorder, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    limits: list[GatewayLimits] = []

    def recording_create_app(*args: Any, **kwargs: Any) -> Any:
        bound = inspect.signature(create_app).bind(*args, **kwargs)
        bound.apply_defaults()
        limits.append(bound.arguments["limits"])
        return create_app(*args, **kwargs)

    monkeypatch.setattr(dev, "create_app", recording_create_app)
    seen: list[tuple[int, Any]] = []
    helper = _terminate_when_serving(recorder, seen)
    assert dev.main(["--port", "0"]) == 0
    assert limits == [GatewayLimits()]
    helper.join(STOP_TIMEOUT_S)
    assert seen == [(200, {"bundles": []})]
    [config] = recorder.configs
    assert config.proxy_headers is False
    assert config.server_header is False
    assert config.access_log is False
    assert "forwarded_allow_ips" not in recorder.config_kwargs[0]
    assert (config.host, config.port) == ("127.0.0.1", 0)
    captured = capsys.readouterr()
    assert GATEWAY_LINE.fullmatch(captured.out.rstrip("\n")) is not None
    assert captured.err == ""


@pytest.fixture
def busy_port() -> Iterator[int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        yield holder.getsockname()[1]


def test_module_exits_one_without_output_when_the_port_is_taken(busy_port: int) -> None:
    result = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "notes_gateway.dev", "--port", str(busy_port)],
        capture_output=True,
        text=True,
        timeout=STOP_TIMEOUT_S,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout == ""


def test_main_returns_one_and_restores_signal_handlers_when_the_port_is_taken(
    busy_port: int, capsys: pytest.CaptureFixture[str]
) -> None:
    before = signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)
    assert dev.main(["--port", str(busy_port)]) == 1
    assert (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT)) == before
    assert capsys.readouterr().out == ""


def test_running_the_module_as_main_exits_with_mains_status(
    busy_port: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["dev.py", "--port", str(busy_port)])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(dev.__file__, run_name="__main__")
    assert stopped.value.code == 1
    assert capsys.readouterr().out == ""


@pytest.fixture
def no_bind(recorder: _Recorder, monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """The `recorder` with `uvicorn.Server.run` a no-op: nothing binds and uvicorn logs nothing."""
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    return recorder


_NON_LOOPBACK = ("192.0.2.1", "0.0.0.0", "::", "", "127.1", "example.com", "::ffff:127.0.0.1")  # noqa: S104 - refused hosts


@pytest.mark.parametrize("host", _NON_LOOPBACK)
def test_main_refuses_a_non_loopback_host_without_the_flag(
    host: str, no_bind: _Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    assert dev.main(["--host", host, "--port", "0"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "NON_LOOPBACK_NOT_ALLOWED\n"
    assert no_bind.configs == []


@pytest.mark.parametrize("host", ["127.5.6.7", "localhost", "::1"])
def test_main_accepts_a_loopback_host_without_the_flag(
    host: str, no_bind: _Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    assert dev.main(["--host", host, "--port", "0"]) == 1
    assert no_bind.configs[0].host == host
    assert capsys.readouterr().err == ""


@pytest.fixture(autouse=True)
def restore_obs_logging() -> Iterator[None]:
    """`main` points the `teecustody` logger at the captured stderr; put it back afterwards."""
    from teecustody.obs import logger as obs_logger

    base = logging.getLogger("teecustody")
    saved = (list(base.handlers), base.level, obs_logger._handler)
    try:
        yield
    finally:
        base.handlers[:] = saved[0]
        base.setLevel(saved[1])
        obs_logger._handler = saved[2]


def test_main_with_the_flag_warns_on_every_start(
    no_bind: _Recorder, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = ["--host", "192.0.2.1", "--port", "0", "--allow-non-loopback"]
    for _ in range(2):
        assert dev.main(argv) == 1
        assert no_bind.configs[-1].host == "192.0.2.1"
        lines = capsys.readouterr().err.splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["level"] == "WARNING"
        assert record["logger"] == "teecustody.gateway"
        assert record["outcome"] == "SIM_NON_LOOPBACK_BIND"
