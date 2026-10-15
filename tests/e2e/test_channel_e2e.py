"""T-31: the end-to-end channel harness as a process (INC-2-API §9.4; API-TL TL-8; FR-4, SR-11).

Every test spawns `tests/e2e/channel_harness.py`, waits a bounded time for its ready line and
kills it on teardown, so a hung harness fails the test instead of hanging the suite.
"""

from __future__ import annotations

import base64
import contextlib
import inspect
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from teecustody.channel.codec import decode_bundle
from teecustody.wire import DecodeLimits

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = REPO_ROOT / "tests" / "e2e" / "channel_harness.py"
READY_LINE = re.compile(
    r"^gateway=http://127\.0\.0\.1:\d+ issuer=http://127\.0\.0\.1:\d+ profile=/\S+$"
)
READY_TIMEOUT_S = 30.0
STOP_TIMEOUT_S = 10.0
BUNDLE_LIMITS = DecodeLimits(max_bytes=65536, max_depth=4, max_items=4096)


class RunningHarness:
    """A harness subprocess with its stdout lines and stderr text collected by reader threads."""

    def __init__(self, argv: list[str]) -> None:
        self.proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, str(HARNESS), *argv],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.lines: list[str] = []
        self.temp_dir: Path | None = None
        self.err: list[str] = []
        self._ready: queue.Queue[str | None] = queue.Queue()
        self._readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self._readers:
            reader.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))
            self._ready.put(self.lines[-1])
        self._ready.put(None)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        self.err.extend(self.proc.stderr)

    def ready_line(self) -> str:
        try:
            line = self._ready.get(timeout=READY_TIMEOUT_S)
        except queue.Empty:
            pytest.fail("harness printed no ready line within 30 s")
        assert line is not None, f"harness exited before ready: {self.proc.poll()}"
        self.temp_dir = Path(line.rsplit("profile=", 1)[1]).parent
        return line

    def terminate(self) -> int:
        self.proc.send_signal(signal.SIGTERM)
        code = self.proc.wait(STOP_TIMEOUT_S)
        self.join()
        return code

    def join(self) -> None:
        for reader in self._readers:
            reader.join(STOP_TIMEOUT_S)
        for pipe in (self.proc.stdout, self.proc.stderr):
            if pipe is not None:
                pipe.close()

    def output(self) -> str:
        return "\n".join(self.lines) + "".join(self.err)

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(STOP_TIMEOUT_S)
        self.join()
        if self.temp_dir is not None and self.temp_dir.name.startswith("tc-e2e-"):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


@pytest.fixture
def harness() -> Iterator[RunningHarness]:
    running = RunningHarness([])
    try:
        yield running
    finally:
        running.kill()


def test_prints_one_ready_line_with_parseable_profile_and_private_fixture(
    harness: RunningHarness,
) -> None:
    line = harness.ready_line()
    assert READY_LINE.fullmatch(line)
    directory = harness.temp_dir
    assert directory is not None
    profile = json.loads((directory / "profile.json").read_text(encoding="utf-8"))
    assert profile["profile_version"] == 2
    fixture_path = directory / "fixture.json"
    assert stat.S_IMODE(os.stat(fixture_path).st_mode) == 0o600
    cs_hex = json.loads(fixture_path.read_text(encoding="utf-8"))["cs"]
    harness.kill()
    assert harness.lines == [line]
    assert cs_hex not in harness.output()


def _get_json(url: str) -> tuple[int, object]:
    assert url.startswith("http://127.0.0.1:")
    with urllib.request.urlopen(url, timeout=STOP_TIMEOUT_S) as response:  # noqa: S310 - loopback
        return response.status, json.loads(response.read())


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_without_the_flag_stdin_eof_does_not_stop_the_harness(harness: RunningHarness) -> None:
    harness.ready_line()
    time.sleep(1.0)
    assert harness.proc.poll() is None
    assert harness.terminate() == 0


def test_gateway_lists_the_one_published_bundle(harness: RunningHarness) -> None:
    gateway = harness.ready_line().split(" ", 1)[0].removeprefix("gateway=")
    status, body = _get_json(f"{gateway}/bundles")
    assert status == 200
    assert isinstance(body, dict)
    [listed] = body["bundles"]
    bundle = decode_bundle(_unb64url(listed["bundle"]), BUNDLE_LIMITS)
    assert bundle.instance_id == listed["instance_id"]
    assert re.fullmatch(r"[0-9a-f]{32}", bundle.instance_id)


def test_sigterm_exits_zero_within_ten_seconds_and_removes_the_temp_dir(
    harness: RunningHarness,
) -> None:
    harness.ready_line()
    directory = harness.temp_dir
    assert directory is not None
    cs_hex = json.loads((directory / "fixture.json").read_text(encoding="utf-8"))["cs"]
    assert harness.terminate() == 0
    assert not directory.exists()
    assert cs_hex not in harness.output()


def test_harness_runs_uvicorn_without_proxy_headers_server_header_or_access_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from notes_gateway import create_app

    from teecustody_sim.backends import InMemoryQueue
    from tests.e2e import channel_harness

    calls: list[dict[str, object]] = []
    real_config = uvicorn.Config

    class RecordingConfig(real_config):  # type: ignore[valid-type,misc]
        def __init__(self, app: object, **kwargs: object) -> None:
            calls.append(kwargs)
            super().__init__(app, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(uvicorn, "Config", RecordingConfig)
    config = channel_harness.server_config(create_app(InMemoryQueue()))
    assert config.proxy_headers is False
    assert config.server_header is False
    assert config.access_log is False
    assert (config.host, config.port) == ("127.0.0.1", 0)
    assert len(calls) == 1
    assert "forwarded_allow_ips" not in calls[0]


def test_harness_gateway_limits_are_the_defaults_except_cors_origins() -> None:
    from notes_gateway import GatewayLimits

    from tests.e2e import channel_harness

    origins = ("http://127.0.0.1:1",)
    assert channel_harness.gateway_limits(origins) == GatewayLimits(cors_origins=origins)


class _ReadyStdout:
    """`sys.stdout` for an in-process harness run; `on_write` runs at the moment of the write."""

    def __init__(self, on_write: Callable[[], None] = lambda: None) -> None:
        self.text = ""
        self.ready = threading.Event()
        self._on_write = on_write

    def write(self, text: str) -> int:
        self._on_write()
        self.text += text
        self.ready.set()
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


def _run_harness_in_process(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], stdout: _ReadyStdout
) -> int:
    """`channel_harness.main` in this (main) thread. A watcher sends SIGTERM once the ready line
    is written or after 30 s, whichever comes first, so a broken harness fails, never hangs. A
    harmless SIGTERM handler stays installed around the run: a late SIGTERM cannot kill pytest."""
    from tests.e2e import channel_harness

    def watch() -> None:
        try:
            stdout.ready.wait(READY_TIMEOUT_S)
        finally:
            os.kill(os.getpid(), signal.SIGTERM)

    previous = signal.signal(signal.SIGTERM, lambda signum, frame: None)
    monkeypatch.setattr(sys, "stdout", stdout)
    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        return channel_harness.main(argv)
    finally:
        stdout.ready.set()  # the watcher fires now, while the harmless handler is installed
        watcher.join(STOP_TIMEOUT_S)
        signal.signal(signal.SIGTERM, previous)


def test_harness_passes_gateway_limits_to_create_app(monkeypatch: pytest.MonkeyPatch) -> None:
    from notes_gateway import GatewayLimits, create_app

    from tests.e2e import channel_harness

    limits: list[GatewayLimits] = []

    def recording_create_app(*args: Any, **kwargs: Any) -> Any:
        bound = inspect.signature(create_app).bind(*args, **kwargs)
        bound.apply_defaults()
        limits.append(bound.arguments["limits"])
        return create_app(*args, **kwargs)

    monkeypatch.setattr(channel_harness, "create_app", recording_create_app)
    origin = "http://127.0.0.1:1"
    stdout = _ReadyStdout()
    assert _run_harness_in_process(monkeypatch, ["--cors-origin", origin], stdout) == 0
    assert READY_LINE.fullmatch(stdout.text.rstrip("\n"))
    assert limits == [GatewayLimits(cors_origins=(origin,))]


def test_ready_line_is_written_only_after_the_first_bundle_is_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from teecustody_sim.backends import InMemoryQueue
    from tests.e2e import channel_harness

    queues: list[InMemoryQueue] = []
    held: list[bool] = []
    listed_at_write: list[bool] = []
    stdout = _ReadyStdout(
        lambda: listed_at_write.append(bool(queues and queues[0].list_bundles(16)))
    )

    class GatedQueue(InMemoryQueue):
        """Holds the first bundle publish for 2 s, or until a ready line is written during it."""

        def __init__(self) -> None:
            super().__init__()
            queues.append(self)

        def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None:
            if not held:
                held.append(stdout.ready.wait(2.0))
            super().publish_bundle(instance_id, bundle, expires_at)

    monkeypatch.setattr(channel_harness, "InMemoryQueue", GatedQueue)
    assert _run_harness_in_process(monkeypatch, [], stdout) == 0
    assert held == [False]  # nothing was written while the first bundle was held back
    assert listed_at_write == [True]
    assert READY_LINE.fullmatch(stdout.text.rstrip("\n"))


RUNNER = (
    "import subprocess, sys, time; "
    "p = subprocess.Popen([sys.executable, sys.argv[1], '--stop-on-stdin-eof'], "
    "stdin=subprocess.PIPE, start_new_session=True); "
    "print(f'pid={p.pid}', flush=True); time.sleep(120)"
)


def _exited(pid: int) -> bool:
    """The process is gone or a zombie (its parent, the runner, never reaps it)."""
    try:
        stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return True
    return stat_line.rsplit(")", 1)[1].split()[0] == "Z"


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


def test_stop_on_stdin_eof_cleans_up_when_the_parent_is_killed() -> None:
    runner = subprocess.Popen(  # noqa: S603 - fixed argv
        [sys.executable, "-c", RUNNER, str(HARNESS)],
        cwd=REPO_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: queue.Queue[str] = queue.Queue()
    collected: list[str] = []

    def read(stream: Any) -> None:
        for text in stream:
            collected.append(text)
            lines.put(text.rstrip("\n"))

    readers = [
        threading.Thread(target=read, args=(runner.stdout,), daemon=True),
        threading.Thread(target=read, args=(runner.stderr,), daemon=True),
    ]
    for reader in readers:
        reader.start()
    harness_pid: int | None = None
    temp_dir: Path | None = None
    try:
        first = lines.get(timeout=READY_TIMEOUT_S)
        assert first.startswith("pid=")
        harness_pid = int(first.removeprefix("pid="))
        deadline = time.monotonic() + READY_TIMEOUT_S
        line = ""
        while not READY_LINE.fullmatch(line):
            assert time.monotonic() < deadline, "harness printed no ready line within 30 s"
            assert not _exited(harness_pid), f"harness exited before ready: {collected[-1:]}"
            with contextlib.suppress(queue.Empty):
                line = lines.get(timeout=0.1)
        temp_dir = Path(line.rsplit("profile=", 1)[1]).parent
        cs_hex = json.loads((temp_dir / "fixture.json").read_text(encoding="utf-8"))["cs"]
        os.kill(runner.pid, signal.SIGKILL)
        runner.wait(STOP_TIMEOUT_S)
        deadline = time.monotonic() + STOP_TIMEOUT_S
        while _group_alive(harness_pid) or temp_dir.exists():
            assert time.monotonic() < deadline, "harness still running 10 s after its parent died"
            time.sleep(0.05)
        for reader in readers:
            reader.join(STOP_TIMEOUT_S)
        assert cs_hex not in "".join(collected)
    finally:
        if harness_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(harness_pid, signal.SIGKILL)
        if runner.poll() is None:
            runner.kill()
            runner.wait(STOP_TIMEOUT_S)
        if temp_dir is not None and temp_dir.name.startswith("tc-e2e-"):
            shutil.rmtree(temp_dir, ignore_errors=True)
        for pipe in (runner.stdout, runner.stderr):
            if pipe is not None:
                pipe.close()
