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
