"""Development entry point (API-TL TL-5): the gateway over the simulator's in-memory queue.

Only this module may import `teecustody_sim`, and only lazily. uvicorn runs with proxy headers,
the server header and the access log off (INC-2-API §6 "Server configuration").
"""

import argparse
import contextlib
import ipaddress
import logging
import signal
import sys
import threading
from collections.abc import Sequence
from types import FrameType

import uvicorn

from notes_gateway.app import create_app
from teecustody.obs import configure_logging, get_logger

_LOOPBACK_V4 = ipaddress.IPv4Network("127.0.0.0/8")
_LOOPBACK_V6 = ipaddress.IPv6Address("::1")
_POLL_S = 0.05
_STOP_TIMEOUT_S = 5.0


def _parse(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m notes_gateway.dev", allow_abbrev=False)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--allow-non-loopback", action="store_true")
    return parser.parse_args(argv)


def _is_loopback(host: str) -> bool:
    """A local copy of the simulator's loopback rule (spec §15.5, T-31 A5)."""
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address in _LOOPBACK_V4
    return address == _LOOPBACK_V6


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the gateway on `--host` (default 127.0.0.1) and `--port` (default 0)."""
    from teecustody_sim.backends import InMemoryQueue

    options = _parse(argv)
    if not options.allow_non_loopback and not _is_loopback(options.host):
        sys.stderr.write("NON_LOOPBACK_NOT_ALLOWED\n")
        return 2
    configure_logging(sys.stderr, logging.WARNING)
    if options.allow_non_loopback:
        get_logger("gateway").warning("SIM_NON_LOOPBACK_BIND")
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
