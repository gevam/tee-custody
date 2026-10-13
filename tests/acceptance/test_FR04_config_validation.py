"""SR-3 / FR-4: workload configuration is validated at construction (INC-2-API §4.4; owner T-09).

Values come from INC-2-API §4.4 and spec §14 defaults. Expected failure on trunk: the invalid
values are accepted (`DID NOT RAISE`), because `__post_init__` validation arrives with T-09.
"""

from typing import Any

import pytest

from teecustody.config import BoundaryLimits, ChannelParams, ConfigError, ConfigErrorCode
from teecustody.wire import DecodeLimits


def _rejected(cls: type, code: ConfigErrorCode, field: str, **kw: Any) -> None:
    with pytest.raises(ConfigError) as exc:
        cls(**kw)
    assert exc.value.code is code and exc.value.field == field
    assert str(exc.value) == f"{code.value}:{field}"


def test_FR04_documented_defaults_are_valid_and_unchanged() -> None:
    # Given validation exists (an out-of-range value is refused)
    _rejected(ChannelParams, ConfigErrorCode.INVALID_PARAMS, "prekey_batch", prekey_batch=0)
    # When no overrides are given
    params, limits = ChannelParams(), BoundaryLimits()
    # Then the INC-2-API §4.4 / spec §14 defaults hold
    assert (params.prekey_ttl_s, params.prekey_batch, params.prekey_low_water) == (3600, 100, 20)
    assert (params.request_skew_s, params.idle_timeout_s, params.refresh_margin_s) == (
        300,
        900,
        300,
    )
    assert limits.pull_max_messages == 32 and limits.max_sessions == 1024
    assert limits.attestation_retry_min_s == 30 and limits.attestation_retry_max_s == 300


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("prekey_ttl_s", 59),
        ("prekey_ttl_s", 3601),
        ("prekey_batch", 0),
        ("prekey_batch", 257),
        ("prekey_low_water", -1),
        ("prekey_low_water", 100),  # must be < batch
        ("request_skew_s", 0),
        ("request_skew_s", 3601),
        ("idle_timeout_s", 0),
        ("idle_timeout_s", 86401),
        ("refresh_margin_s", 0),
        ("refresh_margin_s", 3600),
        ("prekey_ttl_s", True),
        ("prekey_batch", 1.5),
        ("request_skew_s", "300"),
    ],
)
def test_FR04_channel_params_outside_range_are_rejected(field: str, bad: Any) -> None:
    _rejected(ChannelParams, ConfigErrorCode.INVALID_PARAMS, field, **{field: bad})


@pytest.mark.parametrize(
    ("field", "good"),
    [
        ("prekey_ttl_s", 60),
        ("prekey_batch", 256),
        ("prekey_low_water", 0),
        ("refresh_margin_s", 3599),
    ],
)
def test_FR04_channel_params_range_edges_are_accepted(field: str, good: int) -> None:
    # Positive control: the ranges are inclusive, and rejection is not blanket
    _rejected(ChannelParams, ConfigErrorCode.INVALID_PARAMS, "prekey_batch", prekey_batch=0)
    assert getattr(ChannelParams(**{field: good}), field) == good


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("pull_wait_s", 0),
        ("pull_wait_s", -1.0),
        ("pull_wait_s", 30.5),
        ("pull_wait_s", float("nan")),
        ("pull_wait_s", float("inf")),
        ("max_sessions", 0),
        ("max_sessions", True),
        ("max_request_bytes", -5),
        ("pull_max_messages", 0),
        ("replay_cache_max_entries", 0),
        ("audit_aggregate_interval_s", 0),
        ("audit_alert_cap", 0),
        ("attestation_retry_min_s", 0),
        ("session_evict_min_idle_s", 0),
        ("bundle_republish_min_interval_s", 0),
        ("prekey_burn_alert_threshold", 0),
    ],
)
def test_FR04_boundary_limits_that_are_not_finite_positive_are_rejected(
    field: str, bad: Any
) -> None:
    _rejected(BoundaryLimits, ConfigErrorCode.INVALID_LIMITS, field, **{field: bad})


def test_FR04_retry_maximum_below_minimum_is_rejected() -> None:
    with pytest.raises(ConfigError) as exc:
        BoundaryLimits(attestation_retry_min_s=60, attestation_retry_max_s=30)
    assert exc.value.code is ConfigErrorCode.INVALID_LIMITS


@pytest.mark.parametrize(
    "decode",
    [
        DecodeLimits(max_bytes=0, max_depth=2, max_items=16),
        DecodeLimits(max_bytes=1024, max_depth=0, max_items=16),
        DecodeLimits(max_bytes=1024, max_depth=17, max_items=16),
        DecodeLimits(max_bytes=1024, max_depth=2, max_items=0),
    ],
)
def test_FR04_decode_limits_below_one_or_deeper_than_sixteen_are_rejected(
    decode: DecodeLimits,
) -> None:
    for field in ("envelope_decode", "aad_decode", "open_payload_decode", "payload_decode"):
        with pytest.raises(ConfigError) as exc:
            BoundaryLimits(**{field: decode})
        assert exc.value.code is ConfigErrorCode.INVALID_LIMITS and exc.value.field == field
