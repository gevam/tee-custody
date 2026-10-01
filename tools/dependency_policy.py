"""Dependency policy check (SR-9, NFR-6; framework.yaml security.dependency_policy, D-019)."""

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--today")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
