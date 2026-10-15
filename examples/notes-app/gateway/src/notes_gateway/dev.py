"""Development entry point (API-TL TL-5): the gateway over the simulator's in-memory queue.

Only this module may import `teecustody_sim`, and only lazily. uvicorn runs with proxy headers,
the server header and the access log off (INC-2-API §6 "Server configuration").
"""

import argparse
import contextlib
import signal
import sys
import threading
from collections.abc import Sequence
from types import FrameType

import uvicorn

from notes_gateway.app import create_app

_POLL_S = 0.05
_STOP_TIMEOUT_S = 5.0


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m notes_gateway.dev")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the gateway on `--host` (default 127.0.0.1) and `--port` (default 0)."""
    from teecustody_sim.backends import InMemoryQueue

    options = _parse(argv)
    config = uvicorn.Config(
        create_app(InMemoryQueue()),
        host=options.host,
        port=options.port,
        access_log=False,
        proxy_headers=False,
        server_header=False,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    stop = threading.Event()

    def request_stop(signum: int, frame: FrameType | None) -> None:
        stop.set()

    def serve() -> None:
        with contextlib.suppress(SystemExit):  # uvicorn's start-up failure: exit status 1 below
            server.run()

    previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        while thread.is_alive() and not server.started:
            stop.wait(_POLL_S)
        if not server.started:
            return 1
        host, port = server.servers[0].sockets[0].getsockname()[:2]
        sys.stdout.write(f"gateway=http://{host}:{port}\n")
        sys.stdout.flush()
        stop.wait()
    finally:
        server.should_exit = True
        thread.join(_STOP_TIMEOUT_S)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
