"""Support code for INC-1 acceptance tests (QA). Synthetic values only."""

import base64
import json
from dataclasses import dataclass
from typing import Any

from teecustody_sim import Simulator, SimulatorConfig

AUDIENCE = "https://acceptance.teecustody.test/tee"
IMAGE_REFERENCE = "localhost/teecustody-acceptance:1"
IMAGE_DIGEST = "sha256:" + "ab" * 32
START_TIME = 1_900_000_000.0


class FakeClock:
    def __init__(self, now: float = START_TIME) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def decode_jws(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (header, claims) of a compact JWS without verifying it (test-side decoder)."""
    segments = token.split(".")
    assert len(segments) == 3, "compact JWS has three segments"

    def seg(s: str) -> dict[str, Any]:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        value = json.loads(raw)
        assert isinstance(value, dict)
        return value

    return seg(segments[0]), seg(segments[1])


@dataclass
class RunningSim:
    sim: Simulator
    config: SimulatorConfig
    clock: FakeClock
