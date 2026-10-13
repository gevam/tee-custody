"""Channel parameters and boundary limits (INC-2-API §4.4; spec §14 defaults).

Fields and defaults are frozen. Validation (`__post_init__`) belongs to T-09.
"""

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Final

from teecustody.wire.types import DecodeLimits

# Frozen DecodeLimits values used as the BoundaryLimits defaults (INC-2-API §4.4).
_ENVELOPE_DECODE: Final = DecodeLimits(max_bytes=65536, max_depth=2, max_items=16)
_AAD_DECODE: Final = DecodeLimits(max_bytes=512, max_depth=2, max_items=16)
_OPEN_PAYLOAD_DECODE: Final = DecodeLimits(max_bytes=1024, max_depth=2, max_items=16)
_PAYLOAD_DECODE: Final = DecodeLimits(max_bytes=32768, max_depth=16, max_items=4096)


class ConfigErrorCode(StrEnum):
    INVALID_PARAMS = "INVALID_PARAMS"
    INVALID_LIMITS = "INVALID_LIMITS"


class ConfigError(Exception):
    """Carries only a code and the offending field name; `str(err)` is `"<code>:<field>"`."""

    code: ConfigErrorCode
    field: str

    def __init__(self, code: ConfigErrorCode, field: str) -> None:
        super().__init__(f"{code.value}:{field}")
        self.code = code
        self.field = field


_MAX_PULL_WAIT_S: Final = 30
_DECODE_FIELDS: Final = frozenset(
    {"envelope_decode", "aad_decode", "open_payload_decode", "payload_decode"}
)

# Inclusive (low, high) per ChannelParams field; None is unbounded. prekey_low_water's upper
# bound is the cross-field rule `prekey_low_water < prekey_batch`.
_CHANNEL_RANGES: Final[dict[str, tuple[int, int | None]]] = {
    "prekey_ttl_s": (60, 3600),
    "prekey_batch": (1, 256),
    "prekey_low_water": (0, None),
    "request_skew_s": (1, 3600),
    "idle_timeout_s": (1, 86400),
    "refresh_margin_s": (1, 3599),
}


def _int_in_range(value: object, low: int, high: int | None) -> bool:
    """True iff `value` is an exact `int` (not `bool`) in [low, high]; `high=None` is unbounded."""
    return type(value) is int and low <= value and (high is None or value <= high)


def _valid_wait(value: object) -> bool:
    """True iff `value` is an exact `int` or `float` (not `bool`) in (0, 30]; nan and inf fail."""
    if type(value) is not int and type(value) is not float:
        return False
    return 0 < value <= _MAX_PULL_WAIT_S


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelParams:
    prekey_ttl_s: int = 3600  # 60..3600 (bounded by token lifetime, FACTS F-10)
    prekey_batch: int = 100  # 1..256 (wire max per bundle)
    prekey_low_water: int = 20  # 0 <= low_water < batch
    request_skew_s: int = 300  # 1..3600
    idle_timeout_s: int = 900  # 1..86400
    refresh_margin_s: int = 300  # 1..3599; passed to AttestationLifecycle

    def __post_init__(self) -> None:
        for f in fields(self):
            if not _int_in_range(getattr(self, f.name), *_CHANNEL_RANGES[f.name]):
                raise ConfigError(ConfigErrorCode.INVALID_PARAMS, f.name)
        if self.prekey_low_water >= self.prekey_batch:
            raise ConfigError(ConfigErrorCode.INVALID_PARAMS, "prekey_low_water")


@dataclass(frozen=True, slots=True, kw_only=True)
class BoundaryLimits:
    max_token_bytes: int = 16384
    max_request_bytes: int = 65536  # raw envelope bytes, checked before decode
    envelope_decode: DecodeLimits = _ENVELOPE_DECODE
    aad_decode: DecodeLimits = _AAD_DECODE
    open_payload_decode: DecodeLimits = _OPEN_PAYLOAD_DECODE
    payload_decode: DecodeLimits = _PAYLOAD_DECODE
    pull_max_messages: int = 32
    pull_wait_s: float = 1.0  # 0 < x <= 30
    max_sessions: int = 1024
    session_evict_min_idle_s: int = 60  # R-8; 1 <= x <= ChannelParams.idle_timeout_s (RunLoop)
    replay_cache_max_entries: int = 100_000
    audit_aggregate_interval_s: int = 60  # AUDIT_AGGREGATE_INTERVAL
    audit_alert_cap: int = 100  # AUDIT_ALERT_CAP
    prekey_burn_alert_threshold: int = 500  # PREKEY_BURN_ALERT_THRESHOLD, per interval
    attestation_retry_min_s: int = 30  # B-08
    attestation_retry_max_s: int = 300  # B-08; >= retry_min
    bundle_republish_min_interval_s: int = 5

    def __post_init__(self) -> None:
        for f in fields(self):
            if f.name in _DECODE_FIELDS:
                continue
            value = getattr(self, f.name)
            valid = _valid_wait(value) if f.name == "pull_wait_s" else _int_in_range(value, 1, None)
            if not valid:
                raise ConfigError(ConfigErrorCode.INVALID_LIMITS, f.name)
        if self.attestation_retry_max_s < self.attestation_retry_min_s:
            raise ConfigError(ConfigErrorCode.INVALID_LIMITS, "attestation_retry_max_s")
