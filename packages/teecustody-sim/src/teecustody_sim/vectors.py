"""Cross-implementation vector suite and differential corpus generation."""

from pathlib import Path


def generate_suite(out_dir: Path, *, now: int | None = None) -> Path:
    raise NotImplementedError("T-17")


def generate_corpus(out_dir: Path, *, seed: int = 1, count: int = 512) -> Path:
    raise NotImplementedError("T-17")
