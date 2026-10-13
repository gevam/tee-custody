"""Development entry point (API-TL TL-5): the gateway over the simulator's in-memory queue.

Wave-0 stub: T-31 implements it. Only this module may import `teecustody_sim`, and only lazily.
"""

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the gateway on `--host` (default 127.0.0.1) and `--port` (default 0)."""
    raise NotImplementedError("T-31")


if __name__ == "__main__":
    raise SystemExit(main())
