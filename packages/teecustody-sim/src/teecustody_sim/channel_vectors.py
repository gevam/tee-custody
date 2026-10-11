"""Cross-implementation channel vector suite (INC-2-API §5.3; spec/wire/channel-vectors.cddl).

Body belongs to T-25.
"""

from pathlib import Path


def generate_channel_suite(out_dir: Path, *, now: int | None = None) -> Path:
    raise NotImplementedError("T-25")
