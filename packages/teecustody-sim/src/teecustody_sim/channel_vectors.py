"""Cross-implementation channel vector suite (INC-2-API §5.3; spec/wire/channel-vectors.cddl)."""

import time
from pathlib import Path
from typing import Final

from teecustody.wire import PROTO, CanonicalValue, encode

_SUITE_PATH: Final = Path("channel", "suite.cbor")


def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path:
    if now is None:
        now = int(time.time())
    suite: dict[str, CanonicalValue] = {
        "suite": "teecustody-channel-vectors",
        "suite_version": 1,
        "proto": PROTO,
        "generated_at": now,
        "verify_at_ms": now * 1000,
        "profile_json": "",
        "http": {},
        "bundles": [],
        "opens": [],
        "frames": [],
        "results": [],
        "layouts": [],
    }
    path = out_dir / _SUITE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(suite))
    return path
