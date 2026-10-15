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


# INC-2-API §3.2 "Required named cases" and spec/vectors/README.md, transcribed (not imported).
BUNDLE_CASES = (
    "valid",
    "prekey_sig_corrupted",
    "prekey_sig_other_digest",
    "prekey_sig_other_instance",
    "instance_mismatch",
    "ik_nonce_mismatch",
    "all_prekeys_expired",
    "some_prekeys_expired",
    "expired_prekey_sig_corrupted",
    "prekey_ids_unsorted_or_duplicate",
    "published_at_over_max",
    "not_after_over_max",
    "unknown_key",
    "noncanonical",
    "token_dbgstat_enabled",
)
OPEN_CASES = (
    "valid_open_session",
    "valid_enroll",
    "aad_modified",
    "info_other_prekey",
    "ct_truncated",
    "enc_wrong_length",
    "timestamp_over_max",
)
FRAME_NAMES = (
    "valid",
    "seq_equal_last",
    "seq_below_last",
    "seq_above_max",
    "aad_op_modified",
    "aad_session_modified",
    "wrong_key",
    "ct_bitflip",
)
FRAME_CASES = tuple(f"{direction}_{name}" for direction in ("c2t", "t2c") for name in FRAME_NAMES)
RESULT_CASES = (
    "open_ok",
    "open_rejected",
    "open_ok_nil_session",
    "open_error_with_session",
    "open_other_request_id",
    "open_ct_bitflip",
    "frame_ok",
    "frame_re_mismatch",
    "frame_seq_not_above_last",
)
# One accept case per builder, one reject per spec/wire/README.md width/range rule of its inputs.
LAYOUT_INPUTS = {
    "prekey_preimage": ("instance_id", "prekey_id", "pub", "not_after", "image_digest"),
    "hpke_info": ("ik_pub", "prekey_id"),
    "session_nonce": ("seq",),
}
LAYOUT_CASES = tuple(
    case_id
    for kind, fields in LAYOUT_INPUTS.items()
    for case_id in (f"{kind}_accept", *(f"{kind}_{field}_range" for field in fields))
)
NAMED_CASES = {
    "bundles": BUNDLE_CASES,
    "opens": OPEN_CASES,
    "frames": FRAME_CASES,
    "results": RESULT_CASES,
    "layouts": LAYOUT_CASES,
}


@pytest.mark.parametrize(("array", "names"), sorted(NAMED_CASES.items()))
def test_each_array_holds_exactly_its_named_cases_once_in_catalog_order(
    suite: dict[str, Any], array: str, names: tuple[str, ...]
) -> None:
    # Catalog order: the TypeScript contract test compares bundles, opens and results as lists.
    assert [case["id"] for case in suite[array]] == list(names)


def test_layout_and_frame_ids_name_their_kind_and_direction(suite: dict[str, Any]) -> None:
    for case in suite["layouts"]:
        assert case["id"].startswith(f"{case['kind']}_")
    for case in suite["frames"]:
        assert case["id"].startswith(f"{case['direction']}_")
