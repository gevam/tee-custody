"""T-11: audit record validation and canonical JSON (INC-2-API §4.12; SR-6, SR-12, D-007, D-012)."""

import json
import os
import subprocess
import sys
import traceback
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

import pytest

from teecustody.audit import (
    MAX_COUNT,
    AuditClass,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    audit_json,
    validate_audit,
)

HEX = "0123456789abcdef" * 2
TS = 1_800_000_000_000

VALID: list[tuple[AuditKey, AuditRecord]] = [
    (
        AuditKey(AuditClass.EVENT, "event-1"),
        AuditRecord(
            outcome="OPEN_ACCEPTED",
            ts=TS,
            actor_client_id=HEX,
            subject_client_id=HEX,
            recovery_id=HEX,
            request_id=HEX,
            session_id=HEX,
            prekey_id=2**32 - 1,
            epoch=0,
        ),
    ),
    (
        AuditKey(AuditClass.ALERT, f"{HEX}/PREKEY_BURN_HIGH"),
        AuditRecord(outcome="PREKEY_BURN_HIGH", ts=0, request_id=HEX),
    ),
    (
        AuditKey(AuditClass.ALERT, f"{HEX}/ALERT_CAP_REACHED"),
        AuditRecord(
            outcome="ALERT_CAP_REACHED", ts=TS, interval_start=TS - 60_000, interval_end=TS
        ),
    ),
    (
        AuditKey(AuditClass.AGGREGATE, f"{TS - 60_000}/OPEN_FAILED/0011223344556677"),
        AuditRecord(
            outcome="OPEN_FAILED",
            ts=2**53 - 1,
            interval_start=0,
            interval_end=2**53 - 1,
            count=1,
        ),
    ),
    (
        AuditKey(AuditClass.RELEASE, "release_v1-0-0"),
        AuditRecord(outcome="RELEASE_SIGNED", ts=TS),
    ),
]


@pytest.mark.parametrize(
    ("key", "record"), VALID, ids=["event", "alert", "alert-interval", "aggregate", "release"]
)
def test_valid_record_of_each_class_is_accepted(key: AuditKey, record: AuditRecord) -> None:
    assert validate_audit(key, record) is None


EVENT_KEY, EVENT = VALID[0]
ALERT_KEY, ALERT = VALID[2]
AGG_KEY, AGG = VALID[3]
RELEASE_KEY, RELEASE = VALID[4]
IDENTIFIERS = ["actor_client_id", "subject_client_id", "recovery_id", "request_id", "session_id"]
WIDE_INTS = ["ts", "interval_start", "interval_end"]
U32_INTS = ["prekey_id", "epoch"]


class StrSub(str):
    pass


def _case(key: AuditKey, record: AuditRecord, **changes: Any) -> tuple[AuditKey, AuditRecord]:
    return key, replace(record, **changes)


REJECTED: dict[str, tuple[AuditKey, AuditRecord]] = {
    # key: class must be an AuditClass member; id exactly str and AUDIT_ID_PATTERN.fullmatch
    "key-class-plain-str": (AuditKey("EVENT", "event-1"), EVENT),  # type: ignore[arg-type]
    "key-id-newline": (AuditKey(AuditClass.EVENT, "event-1\n"), EVENT),
    "key-id-traversal": (AuditKey(AuditClass.EVENT, "../event-1"), EVENT),
    "key-id-empty": (AuditKey(AuditClass.EVENT, ""), EVENT),
    "key-id-too-many-segments": (AuditKey(AuditClass.EVENT, "a/b/c/d"), EVENT),
    "key-id-not-str": (AuditKey(AuditClass.EVENT, b"event-1"), EVENT),  # type: ignore[arg-type]
    "key-id-str-subclass": (AuditKey(AuditClass.EVENT, StrSub("event-1")), EVENT),
    # outcome: exactly str and OUTCOME_PATTERN.fullmatch
    "outcome-free-text": _case(EVENT_KEY, EVENT, outcome="not a code"),
    "outcome-newline": _case(EVENT_KEY, EVENT, outcome="OPEN_ACCEPTED\n"),
    "outcome-lowercase": _case(EVENT_KEY, EVENT, outcome="open_accepted"),
    "outcome-empty": _case(EVENT_KEY, EVENT, outcome=""),
    "outcome-not-str": _case(EVENT_KEY, EVENT, outcome=1),
    "outcome-str-subclass": _case(EVENT_KEY, EVENT, outcome=StrSub("OPEN_ACCEPTED")),
}
for name in IDENTIFIERS:
    REJECTED[f"{name}-newline"] = _case(EVENT_KEY, EVENT, **{name: HEX + "\n"})
    REJECTED[f"{name}-uppercase"] = _case(EVENT_KEY, EVENT, **{name: HEX.upper()})
    REJECTED[f"{name}-short"] = _case(EVENT_KEY, EVENT, **{name: HEX[:-1]})
    REJECTED[f"{name}-long"] = _case(EVENT_KEY, EVENT, **{name: HEX + "0"})
    REJECTED[f"{name}-not-str"] = _case(EVENT_KEY, EVENT, **{name: HEX.encode()})
    REJECTED[f"{name}-str-subclass"] = _case(EVENT_KEY, EVENT, **{name: StrSub(HEX)})
for name in WIDE_INTS:
    REJECTED[f"{name}-bool"] = _case(AGG_KEY, AGG, **{name: True})
    REJECTED[f"{name}-negative"] = _case(AGG_KEY, AGG, **{name: -1})
    REJECTED[f"{name}-over-2^53-1"] = _case(AGG_KEY, AGG, **{name: 2**53})
    REJECTED[f"{name}-float"] = _case(AGG_KEY, AGG, **{name: 1.0})
for name in U32_INTS:
    REJECTED[f"{name}-bool"] = _case(EVENT_KEY, EVENT, **{name: True})
    REJECTED[f"{name}-negative"] = _case(EVENT_KEY, EVENT, **{name: -1})
    REJECTED[f"{name}-over-2^32-1"] = _case(EVENT_KEY, EVENT, **{name: 2**32})
    REJECTED[f"{name}-str"] = _case(EVENT_KEY, EVENT, **{name: "1"})
REJECTED.update(
    {
        "ts-missing": _case(EVENT_KEY, EVENT, ts=None),
        # interval rules
        "interval-on-event": _case(EVENT_KEY, EVENT, interval_start=1, interval_end=2),
        "interval-on-release": _case(RELEASE_KEY, RELEASE, interval_start=1, interval_end=2),
        "interval-end-only-on-event": _case(EVENT_KEY, EVENT, interval_end=2),
        "interval-start-only-on-alert": _case(ALERT_KEY, ALERT, interval_end=None),
        "interval-end-only-on-alert": _case(ALERT_KEY, ALERT, interval_start=None),
        "interval-start-only-on-aggregate": _case(AGG_KEY, AGG, interval_end=None),
        "interval-missing-on-aggregate": _case(
            AGG_KEY, AGG, interval_start=None, interval_end=None
        ),
        "interval-empty-on-alert": _case(ALERT_KEY, ALERT, interval_start=TS, interval_end=TS),
        "interval-empty-on-aggregate": _case(AGG_KEY, AGG, interval_start=5, interval_end=5),
        "interval-reversed-on-aggregate": _case(AGG_KEY, AGG, interval_start=6, interval_end=5),
        # count rules (SR-6 / D-012)
        "count-on-event": _case(EVENT_KEY, EVENT, count=1),
        "count-on-alert": _case(ALERT_KEY, ALERT, count=1),
        "count-on-release": _case(RELEASE_KEY, RELEASE, count=1),
        "count-missing-on-aggregate": _case(AGG_KEY, AGG, count=None),
        "count-zero": _case(AGG_KEY, AGG, count=0),
        "count-over-max": _case(AGG_KEY, AGG, count=MAX_COUNT + 1),
        "count-bool": _case(AGG_KEY, AGG, count=True),
    }
)


@pytest.mark.parametrize(("key", "record"), list(REJECTED.values()), ids=list(REJECTED))
def test_out_of_contract_record_is_rejected_with_only_the_code(
    key: AuditKey, record: AuditRecord
) -> None:
    with pytest.raises(AuditError) as caught:
        validate_audit(key, record)
    assert caught.value.code is AuditErrorCode.INVALID_ARGUMENT
    assert str(caught.value) == "INVALID_ARGUMENT"


def test_count_at_max_is_accepted() -> None:
    assert validate_audit(AGG_KEY, replace(AGG, count=MAX_COUNT)) is None


def test_identifier_pattern_is_the_channel_hex32_pattern() -> None:
    from teecustody.audit import validate as validate_module
    from teecustody.channel.codec import HEX32_PATTERN

    assert validate_module._HEX32_PATTERN.pattern == HEX32_PATTERN.pattern
    assert validate_module._HEX32_PATTERN.flags == HEX32_PATTERN.flags


def test_audit_json_is_the_documented_canonical_form() -> None:
    expected = json.dumps(
        {
            "actor_client_id": HEX,
            "epoch": 0,
            "outcome": "OPEN_ACCEPTED",
            "prekey_id": 2**32 - 1,
            "recovery_id": HEX,
            "request_id": HEX,
            "session_id": HEX,
            "subject_client_id": HEX,
            "ts": TS,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    assert audit_json(EVENT) == expected


def test_audit_json_omits_none_fields_and_sorts_keys() -> None:
    assert audit_json(AGG) == (
        b'{"count":1,"interval_end":9007199254740991,"interval_start":0,'
        b'"outcome":"OPEN_FAILED","ts":9007199254740991}'
    )
    assert audit_json(RELEASE) == b'{"outcome":"RELEASE_SIGNED","ts":1800000000000}'


def test_audit_json_escapes_non_ascii_and_returns_bytes() -> None:
    body = audit_json(AuditRecord(outcome="\u00e9", ts=1))
    assert body == b'{"outcome":"\\u00e9","ts":1}'
    assert type(body) is bytes


def test_audit_json_is_stable_across_runs() -> None:
    script = (
        "from teecustody.audit import AuditRecord, audit_json;"
        "import sys;"
        f"sys.stdout.buffer.write(audit_json(AuditRecord(outcome='X', ts=1, epoch=2, "
        f"session_id='{HEX}', request_id='{HEX}', count=3)))"
    )
    runs = {
        subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout
        for seed in ("0", "1", "random")
    }
    assert runs == {
        b'{"count":3,"epoch":2,"outcome":"X","request_id":"'
        + HEX.encode()
        + b'","session_id":"'
        + HEX.encode()
        + b'","ts":1}'
    }


SENTINEL = "SENTINEL-c2hhcmUtc2VjcmV0-9f3a"
LEAK_CASES = {
    "outcome": _case(EVENT_KEY, EVENT, outcome=SENTINEL),
    "key-id": (AuditKey(AuditClass.EVENT, f"event/{SENTINEL}/x y"), EVENT),
    "request-id": _case(EVENT_KEY, EVENT, request_id=SENTINEL),
    "subject-client-id": _case(EVENT_KEY, EVENT, subject_client_id=SENTINEL),
}


@pytest.mark.parametrize(("key", "record"), list(LEAK_CASES.values()), ids=list(LEAK_CASES))
def test_rejection_never_echoes_the_offending_value(key: AuditKey, record: AuditRecord) -> None:
    with pytest.raises(AuditError) as caught:
        validate_audit(key, record)
    err = caught.value
    assert err.code is AuditErrorCode.INVALID_ARGUMENT
    assert err.args == ("INVALID_ARGUMENT",)
    assert err.__cause__ is None
    assert err.__context__ is None
    rendered = str(err) + repr(err) + "".join(traceback.format_exception(err))
    assert SENTINEL not in rendered


@dataclass(frozen=True, slots=True, kw_only=True)
class LeakyRecord(AuditRecord):
    body: str = SENTINEL


@dataclass(frozen=True, slots=True)
class LeakyKey(AuditKey):
    body: str = SENTINEL


LEAKY = LeakyRecord(outcome="OPEN_ACCEPTED", ts=TS)
DUCK_RECORD = SimpleNamespace(outcome="OPEN_ACCEPTED", ts=TS, body=SENTINEL)
NOT_RECORDS = {
    "record-subclass": (EVENT_KEY, LEAKY),
    "record-duck": (EVENT_KEY, DUCK_RECORD),
    "key-subclass": (LeakyKey(AuditClass.EVENT, "event-1"), EVENT),
    "key-duck": (SimpleNamespace(record_class=AuditClass.EVENT, id="event-1"), EVENT),
}


@pytest.mark.parametrize(("key", "record"), list(NOT_RECORDS.values()), ids=list(NOT_RECORDS))
def test_validate_rejects_anything_but_exact_key_and_record_types(key: Any, record: Any) -> None:
    with pytest.raises(AuditError) as caught:
        validate_audit(key, record)
    assert str(caught.value) == "INVALID_ARGUMENT"


def test_audit_json_serialises_only_audit_record_fields_of_a_subclass() -> None:
    assert audit_json(LEAKY) == b'{"outcome":"OPEN_ACCEPTED","ts":1800000000000}'


def test_audit_json_rejects_a_duck_typed_record_with_only_the_code() -> None:
    with pytest.raises(AuditError) as caught:
        audit_json(DUCK_RECORD)  # type: ignore[arg-type]
    assert str(caught.value) == "INVALID_ARGUMENT"
    assert caught.value.__context__ is None
