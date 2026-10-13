"""T-09: `ChannelParams` and `BoundaryLimits` validation (INC-2-API §4.4; SR-3, SR-4, NFR-9)."""

from __future__ import annotations

import math
from typing import Any

import pytest

from teecustody.config import BoundaryLimits, ChannelParams, ConfigError, ConfigErrorCode
from teecustody.wire import DecodeLimits

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
_HUGE: list[Any] = [10**18, 1e18]

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
    for bad in [*_NOT_INT, *_HUGE]
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

# Inclusive (low, high) per BoundaryLimits int field: the INC-2-API §4.4 bounds table.
LIMIT_INT_RANGES: dict[str, tuple[int, int]] = {
    "max_token_bytes": (1024, 16384),
    "max_request_bytes": (1024, 65536),
    "pull_max_messages": (1, 1000),
    "max_sessions": (1, 65536),
    "session_evict_min_idle_s": (1, 86400),
    "replay_cache_max_entries": (1, 1_000_000),
    "audit_aggregate_interval_s": (10, 900),
    "audit_alert_cap": (1, 10_000),
    "prekey_burn_alert_threshold": (1, 10_000),
    "attestation_retry_min_s": (1, 300),
    "attestation_retry_max_s": (30, 3600),  # low end is the default retry min (criterion 5)
    "bundle_republish_min_interval_s": (1, 300),
}

# The decode limits must fit inside the smallest max_request_bytes (decode max_bytes rule).
_FITS_1024: dict[str, Any] = {
    "envelope_decode": DecodeLimits(max_bytes=1024, max_depth=2, max_items=16),
    "payload_decode": DecodeLimits(max_bytes=1024, max_depth=16, max_items=1024),
}


@pytest.mark.parametrize(
    ("field", "value"),
    [(field, value) for field, bounds in LIMIT_INT_RANGES.items() for value in bounds],
)
def test_boundary_limit_int_fields_accept_range_edges(field: str, value: int) -> None:
    limits = BoundaryLimits(**{**_FITS_1024, field: value})
    assert getattr(limits, field) == value


@pytest.mark.parametrize(
    "value",
    [0.01, 0.5, 1, 1.0, 29.999, 30, 30.0],
    ids=lambda v: f"{type(v).__name__}-{v}",
)
def test_pull_wait_accepts_int_or_float_in_closed_range(value: float) -> None:
    assert BoundaryLimits(pull_wait_s=value).pull_wait_s == value


LIMIT_INT_INVALID: list[tuple[str, Any]] = [
    (field, bad)
    for field, (low, high) in LIMIT_INT_RANGES.items()
    for bad in [low - 1, high + 1, 0, -1, *_NOT_INT, *_HUGE]
]


@pytest.mark.parametrize(("field", "bad"), LIMIT_INT_INVALID)
def test_boundary_limit_int_fields_reject_invalid_value(field: str, bad: Any) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: bad})


@pytest.mark.parametrize(
    "bad",
    [
        *(0, 0.0, -0.0, -1, -1.0, 5e-324, 0.001, math.nextafter(0.01, 0.0)),
        *(math.nextafter(30.0, math.inf), 31, 1e18, 10**18),
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


# --- criterion 6: DecodeLimits fields -----------------------------------------------------------

DECODE_FIELDS: tuple[str, ...] = (
    "envelope_decode",
    "aad_decode",
    "open_payload_decode",
    "payload_decode",
)


def _decode(**overrides: Any) -> DecodeLimits:
    values: dict[str, Any] = {"max_bytes": 1024, "max_depth": 2, "max_items": 16}
    values.update(overrides)
    return DecodeLimits(**values)


# Fixed max_bytes cap per decode field (INC-2-API §4.4); envelope_decode is capped only by
# max_request_bytes, whose default is 65536.
DECODE_MAX_BYTES: dict[str, int] = {
    "envelope_decode": 65536,
    "aad_decode": 1024,
    "open_payload_decode": 2048,
    "payload_decode": 32768,
}


@pytest.mark.parametrize("field", DECODE_FIELDS)
@pytest.mark.parametrize("edge", ["lowest", "highest"])
def test_decode_limit_fields_accept_range_edges(field: str, edge: str) -> None:
    cap = DECODE_MAX_BYTES[field]
    limits = _decode(max_bytes=1, max_depth=1, max_items=1)
    if edge == "highest":
        limits = _decode(max_bytes=cap, max_depth=16, max_items=cap)
    assert getattr(BoundaryLimits(**{field: limits}), field) == limits


_BAD_DECODE: list[DecodeLimits] = [
    *(
        _decode(**{name: bad})
        for name in ("max_bytes", "max_depth", "max_items")
        for bad in [0, -1, *_NOT_INT, *_HUGE]
    ),
    _decode(max_depth=17),
    _decode(max_bytes=16, max_items=17),  # an item takes at least one byte
]


@pytest.mark.parametrize("field", DECODE_FIELDS)
@pytest.mark.parametrize("bad", _BAD_DECODE, ids=repr)
def test_decode_limit_fields_reject_invalid_limits(field: str, bad: DecodeLimits) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: bad})


@pytest.mark.parametrize("field", DECODE_FIELDS)
def test_decode_max_bytes_above_its_cap_is_rejected(field: str) -> None:
    bad = _decode(max_bytes=DECODE_MAX_BYTES[field] + 1)
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: bad})


@pytest.mark.parametrize("field", DECODE_FIELDS)
@pytest.mark.parametrize("bad", [None, 1024, {"max_bytes": 1, "max_depth": 1, "max_items": 1}])
def test_decode_limit_fields_reject_values_that_are_not_decode_limits(field: str, bad: Any) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: bad})


class _ShiftingDecodeLimits(DecodeLimits):
    """Overrides `max_items` with a property: valid on its first read, unbounded afterwards."""

    reads: int

    def __init__(self) -> None:
        object.__setattr__(self, "max_bytes", 1024)
        object.__setattr__(self, "max_depth", 2)
        object.__setattr__(self, "reads", 0)

    @property  # type: ignore[override]
    def max_items(self) -> int:
        object.__setattr__(self, "reads", self.reads + 1)
        return 16 if self.reads == 1 else 2**62


@pytest.mark.parametrize("field", DECODE_FIELDS)
def test_decode_limits_subclass_is_rejected(field: str) -> None:
    _assert_rejected(BoundaryLimits, LIMITS, field, **{field: _ShiftingDecodeLimits()})


# --- decode max_bytes <= max_request_bytes (cross-field) -------------------------------------

_DECODE_AT_2048: dict[str, Any] = {
    "envelope_decode": _decode(max_bytes=2048),
    "payload_decode": _decode(max_bytes=2048),
}


def test_decode_max_bytes_equal_to_max_request_bytes_is_accepted() -> None:
    limits = BoundaryLimits(max_request_bytes=2048, **_DECODE_AT_2048)
    assert limits.envelope_decode.max_bytes == limits.max_request_bytes == 2048


@pytest.mark.parametrize("field", ["envelope_decode", "payload_decode"])
def test_decode_max_bytes_above_max_request_bytes_is_rejected(field: str) -> None:
    kwargs = {**_DECODE_AT_2048, field: _decode(max_bytes=2049)}
    _assert_rejected(BoundaryLimits, LIMITS, field, max_request_bytes=2048, **kwargs)


def test_decode_cross_rule_is_checked_after_every_single_field_rule() -> None:
    _assert_rejected(
        BoundaryLimits,
        LIMITS,
        "bundle_republish_min_interval_s",
        max_request_bytes=2048,
        bundle_republish_min_interval_s=0,
    )


def test_decode_cross_rule_is_reported_before_the_retry_rule() -> None:
    _assert_rejected(
        BoundaryLimits,
        LIMITS,
        "envelope_decode",
        max_request_bytes=2048,
        attestation_retry_min_s=60,
        attestation_retry_max_s=30,
    )


# --- criterion 7: the INC-2-API §4.4 examples ---------------------------------------------------


def test_documented_examples() -> None:
    assert BoundaryLimits(max_sessions=64).max_sessions == 64
    with pytest.raises(ConfigError) as excinfo:
        BoundaryLimits(pull_wait_s=0)
    assert str(excinfo.value) == "INVALID_LIMITS:pull_wait_s"
