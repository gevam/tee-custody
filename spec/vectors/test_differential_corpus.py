"""Differential corpus conformance (ADR 0010; API.md §F; SR-3).

Each case is a seeded mutation of a valid canonical encoding with the Python codec's recorded
outcome. The TypeScript codec is held to the same outcomes by its own suite.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from teecustody.wire import DecodeLimits, WireError, decode, encode

OUTCOMES = frozenset(
    {"accept", "TOO_LARGE", "MALFORMED", "NONCANONICAL", "UNSUPPORTED_TYPE", "LIMIT_EXCEEDED"}
)
HEX = re.compile(r"(?:[0-9a-f]{2})*")
MINIMUM_CASES = 500


def _outcome(data: bytes, limits: DecodeLimits) -> str:
    try:
        decode(data, limits)
    except WireError as error:
        return error.code.value
    return "accept"


def test_corpus_has_the_documented_shape(
    differential_corpus: dict[str, Any], require_int: Callable[[object], int]
) -> None:
    assert set(differential_corpus) == {"format", "version", "seed", "limits", "cases"}
    assert differential_corpus["format"] == "teecustody-cbor-differential-corpus"
    assert require_int(differential_corpus["version"]) == 1
    require_int(differential_corpus["seed"])
    limits = differential_corpus["limits"]
    assert {name: require_int(value) for name, value in limits.items()} == {
        "max_bytes": 1024,
        "max_depth": 8,
        "max_items": 256,
    }
    assert type(differential_corpus["cases"]) is list
    for case in differential_corpus["cases"]:
        assert set(case) == {"id", "hex", "outcome"}, case
        assert type(case["id"]) is str
        assert type(case["hex"]) is str
        assert HEX.fullmatch(case["hex"]), case["id"]
        assert case["outcome"] in OUTCOMES, case["id"]


def test_corpus_has_enough_cases_with_unique_ids(differential_corpus: dict[str, Any]) -> None:
    ids = [case["id"] for case in differential_corpus["cases"]]
    assert len(ids) >= MINIMUM_CASES
    assert len(ids) == len(set(ids))


def test_python_codec_reproduces_every_recorded_outcome(
    differential_corpus: dict[str, Any], corpus_limits: DecodeLimits
) -> None:
    mismatches = [
        (case["id"], case["outcome"], actual)
        for case in differential_corpus["cases"]
        if (actual := _outcome(bytes.fromhex(case["hex"]), corpus_limits)) != case["outcome"]
    ]
    assert mismatches == []


def test_accepted_cases_re_encode_to_identical_bytes(
    differential_corpus: dict[str, Any], corpus_limits: DecodeLimits
) -> None:
    """Checked here, not left to the codec's own re-encode check (rule 4)."""
    accepted = [
        bytes.fromhex(case["hex"])
        for case in differential_corpus["cases"]
        if case["outcome"] == "accept"
    ]
    assert accepted
    assert [data.hex() for data in accepted if encode(decode(data, corpus_limits)) != data] == []
