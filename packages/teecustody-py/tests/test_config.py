"""T-09: `ChannelParams` and `BoundaryLimits` validation (INC-2-API §4.4; SR-3, SR-4, NFR-9)."""

from __future__ import annotations

from typing import Any

import pytest

from teecustody.config import BoundaryLimits, ChannelParams, ConfigError, ConfigErrorCode

PARAMS = ConfigErrorCode.INVALID_PARAMS
LIMITS = ConfigErrorCode.INVALID_LIMITS


def _assert_rejected(cls: type, code: ConfigErrorCode, field: str, **kwargs: Any) -> None:
    with pytest.raises(ConfigError) as excinfo:
        cls(**kwargs)
    assert excinfo.value.code is code
    assert excinfo.value.field == field
    assert str(excinfo.value) == f"{code.value}:{field}"


# --- criterion 1: defaults construct ---------------------------------------------------------


def test_defaults_construct() -> None:
    assert ChannelParams() == ChannelParams()
    assert BoundaryLimits() == BoundaryLimits()


# --- criterion 2: every ChannelParams field accepts its lowest and highest valid value --------

CHANNEL_VALID: list[tuple[str, int]] = [
    ("prekey_ttl_s", 60),
    ("prekey_ttl_s", 3600),
    ("prekey_batch", 21),  # lowest above the default low water of 20
    ("prekey_batch", 256),
    ("prekey_low_water", 0),
    ("prekey_low_water", 99),  # default batch - 1
    ("request_skew_s", 1),
    ("request_skew_s", 3600),
    ("idle_timeout_s", 1),
    ("idle_timeout_s", 86400),
    ("refresh_margin_s", 1),
    ("refresh_margin_s", 3599),
]


@pytest.mark.parametrize(("field", "value"), CHANNEL_VALID)
def test_channel_params_accept_range_edges(field: str, value: int) -> None:
    assert getattr(ChannelParams(**{field: value}), field) == value


def test_channel_params_accept_smallest_batch_with_zero_low_water() -> None:
    params = ChannelParams(prekey_batch=1, prekey_low_water=0)
    assert (params.prekey_batch, params.prekey_low_water) == (1, 0)


# --- criterion 3: every ChannelParams field rejects out-of-range and wrongly typed values -----

_NOT_INT: list[Any] = [True, False, "300", 1.0, 1.5, None]

CHANNEL_INVALID: list[tuple[str, Any]] = [
    ("prekey_ttl_s", 59),
    ("prekey_ttl_s", 3601),
    ("prekey_ttl_s", 0),
    ("prekey_ttl_s", -1),
    ("prekey_batch", 0),
    ("prekey_batch", 257),
    ("prekey_batch", -1),
    ("prekey_low_water", -1),
    ("request_skew_s", 0),
    ("request_skew_s", 3601),
    ("request_skew_s", -1),
    ("idle_timeout_s", 0),
    ("idle_timeout_s", 86401),
    ("idle_timeout_s", -1),
    ("refresh_margin_s", 0),
    ("refresh_margin_s", 3600),
    ("refresh_margin_s", -1),
] + [
    (field, bad)
    for field in (
        "prekey_ttl_s",
        "prekey_batch",
        "prekey_low_water",
        "request_skew_s",
        "idle_timeout_s",
        "refresh_margin_s",
    )
    for bad in _NOT_INT
]


@pytest.mark.parametrize(("field", "bad"), CHANNEL_INVALID)
def test_channel_params_reject_invalid_value(field: str, bad: Any) -> None:
    _assert_rejected(ChannelParams, PARAMS, field, **{field: bad})


# --- criterion 4: prekey_low_water < prekey_batch ---------------------------------------------


@pytest.mark.parametrize(("batch", "low_water"), [(100, 100), (100, 101), (1, 1), (10, 256)])
def test_low_water_not_below_batch_is_rejected(batch: int, low_water: int) -> None:
    _assert_rejected(
        ChannelParams, PARAMS, "prekey_low_water", prekey_batch=batch, prekey_low_water=low_water
    )


def test_cross_field_rule_is_checked_after_every_single_field_rule() -> None:
    _assert_rejected(
        ChannelParams, PARAMS, "refresh_margin_s", prekey_low_water=500, refresh_margin_s=0
    )


def test_first_failing_field_in_declaration_order_is_reported() -> None:
    _assert_rejected(ChannelParams, PARAMS, "prekey_ttl_s", prekey_ttl_s=0, prekey_batch=0)


# --- criteria 2-3: BoundaryLimits int fields and pull_wait_s ----------------------------------

LIMIT_INT_FIELDS: tuple[str, ...] = (
    "max_token_bytes",
    "max_request_bytes",
    "pull_max_messages",
    "max_sessions",
    "session_evict_min_idle_s",
    "replay_cache_max_entries",
    "audit_aggregate_interval_s",
    "audit_alert_cap",
    "prekey_burn_alert_threshold",
    "attestation_retry_min_s",
    "attestation_retry_max_s",
    "bundle_republish_min_interval_s",
)

# attestation_retry_min_s is capped at the default retry max (300) by the cross-field rule.
_LIMIT_INT_HIGH: dict[str, int] = {"attestation_retry_min_s": 300}


@pytest.mark.parametrize("field", LIMIT_INT_FIELDS)
def test_boundary_limit_int_fields_accept_range_edges(field: str) -> None:
    low = 30 if field == "attestation_retry_max_s" else 1  # >= default retry min
    high = _LIMIT_INT_HIGH.get(field, 2**63)
    for value in (low, high):
        assert getattr(BoundaryLimits(**{field: value}), field) == value


@pytest.mark.parametrize(
    "value", [5e-324, 0.001, 1, 1.0, 29.999, 30, 30.0], ids=lambda v: f"{type(v).__name__}-{v}"
)
def test_pull_wait_accepts_int_or_float_in_half_open_range(value: float) -> None:
    assert BoundaryLimits(pull_wait_s=value).pull_wait_s == value


LIMIT_INT_INVALID: list[tuple[str, Any]] = [
    (field, bad) for field in LIMIT_INT_FIELDS for bad in [0, -1, *_NOT_INT]
]


@pytest.mark.parametrize(("field", "bad"), LIMIT_INT_INVALID)
def test_boundary_limit_int_fields_reject_invalid_value(field: str, bad: Any) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: bad})


@pytest.mark.parametrize(
    "bad",
    [
        *(0, 0.0, -0.0, -1, -1.0, 30.000001, 31),
        *(float("nan"), float("inf"), float("-inf")),
        *(True, False, "1.0", None),
    ],
    ids=repr,
)
def test_pull_wait_rejects_invalid_value(bad: Any) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, "pull_wait_s", pull_wait_s=bad)


# --- criterion 5: attestation_retry_max_s >= attestation_retry_min_s -----------------------


def test_retry_max_below_min_is_rejected() -> None:
    _assert_rejected(
        BoundaryLimits,
        LIMITS,
        "attestation_retry_max_s",
        attestation_retry_min_s=60,
        attestation_retry_max_s=59,
    )


def test_retry_max_equal_to_min_is_accepted() -> None:
    limits = BoundaryLimits(attestation_retry_min_s=60, attestation_retry_max_s=60)
    assert (limits.attestation_retry_min_s, limits.attestation_retry_max_s) == (60, 60)


def test_retry_rule_is_checked_after_every_single_field_rule() -> None:
    _assert_rejected(
        BoundaryLimits,
        LIMITS,
        "bundle_republish_min_interval_s",
        attestation_retry_min_s=60,
        attestation_retry_max_s=30,
        bundle_republish_min_interval_s=0,
    )


def test_first_failing_limit_in_declaration_order_is_reported() -> None:
    _assert_rejected(BoundaryLimits, LIMITS, "max_token_bytes", max_token_bytes=0, max_sessions=0)
