"""T-25: the channel vector suite generator (INC-2-API §3.2, §5.3, §16.4; channel-vectors.cddl).

Every check here is computed by the test itself (its own Ed25519, HPKE and AES-GCM operations and
its own byte layouts), never by the generator's helpers: the suite is checked against the
specification, not against the code that produced it (SR-14, NFR-7).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import PROTO, DecodeLimits, decode
from teecustody_sim.channel_vectors import generate_channel_suite

NOW = 1_900_000_000
CHANNEL_SUITE_LIMITS = DecodeLimits(max_bytes=4_194_304, max_depth=8, max_items=65_536)
SUITE_KEYS = {
    "suite",
    "suite_version",
    "proto",
    "generated_at",
    "verify_at_ms",
    "profile_json",
    "http",
    "bundles",
    "opens",
    "frames",
    "results",
    "layouts",
}


def _load(path: Path) -> dict[str, Any]:
    decoded = decode(path.read_bytes(), CHANNEL_SUITE_LIMITS)
    assert isinstance(decoded, dict)
    return decoded


@pytest.fixture(scope="module")
def suite_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_channel_suite(tmp_path_factory.mktemp("channel"), now=NOW)


@pytest.fixture(scope="module")
def suite(suite_path: Path) -> dict[str, Any]:
    return _load(suite_path)


def test_suite_is_written_under_channel_and_has_exactly_the_cddl_keys(
    suite_path: Path, suite: dict[str, Any]
) -> None:
    assert suite_path.relative_to(suite_path.parent.parent) == Path("channel", "suite.cbor")
    assert set(suite) == SUITE_KEYS
    assert suite["suite"] == "teecustody-channel-vectors"
    assert suite["suite_version"] == 1
    assert suite["proto"] == PROTO
    assert suite["generated_at"] == NOW
    assert suite["verify_at_ms"] == NOW * 1000


def test_now_defaults_to_the_current_time(tmp_path: Path) -> None:
    before = int(time.time())
    generated = _load(generate_channel_suite(tmp_path))["generated_at"]
    assert before <= generated <= int(time.time())
