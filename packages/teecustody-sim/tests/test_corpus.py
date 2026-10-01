"""T-17: differential CBOR corpus generator (API.md §C vectors.py, §F; ADR 0010; SR-3)."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from teecustody.wire import DecodeLimits, WireError, WireErrorCode, decode, encode
from teecustody_sim import generate_corpus

CORPUS_LIMITS = DecodeLimits(max_bytes=1024, max_depth=8, max_items=256)
CASE_ID = re.compile(r"m[0-9]{4}")
HEX = re.compile(r"(?:[0-9a-f]{2})*")


def _outcome(data: bytes) -> str:
    try:
        decode(data, CORPUS_LIMITS)
    except WireError as error:
        return error.code.value
    return "accept"


def _read(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


@pytest.fixture(scope="module")
def corpus_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return generate_corpus(tmp_path_factory.mktemp("corpus"))


@pytest.fixture(scope="module")
def corpus(corpus_path: Path) -> dict[str, Any]:
    return _read(corpus_path)


def test_corpus_is_written_under_wire_in_the_output_directory(corpus_path: Path) -> None:
    assert corpus_path.name == "differential-corpus.json"
    assert corpus_path.parent.name == "wire"


def test_corpus_has_the_documented_format(corpus_path: Path, corpus: dict[str, Any]) -> None:
    assert set(corpus) == {"format", "version", "seed", "limits", "cases"}
    assert corpus["format"] == "teecustody-cbor-differential-corpus"
    assert corpus["version"] == 1
    assert corpus["seed"] == 1
    assert corpus["limits"] == {"max_bytes": 1024, "max_depth": 8, "max_items": 256}
    for case in corpus["cases"]:
        assert set(case) == {"id", "hex", "outcome"}
        assert HEX.fullmatch(case["hex"])
    assert corpus_path.read_text(encoding="utf-8") == json.dumps(
        corpus, indent=None, sort_keys=True, separators=(",", ":")
    )


def test_same_seed_gives_byte_identical_files(tmp_path: Path, corpus_path: Path) -> None:
    again = generate_corpus(tmp_path / "again", seed=1)

    assert again.read_bytes() == corpus_path.read_bytes()


def test_seed_selects_the_corpus(tmp_path: Path, corpus: dict[str, Any]) -> None:
    other = _read(generate_corpus(tmp_path, seed=2, count=500))

    assert other["seed"] == 2
    assert [case["hex"] for case in other["cases"]] != [case["hex"] for case in corpus["cases"]]


def test_default_corpus_has_512_cases_with_sequential_unique_ids(corpus: dict[str, Any]) -> None:
    ids = [case["id"] for case in corpus["cases"]]

    assert ids == [f"m{index:04d}" for index in range(512)]
    assert all(CASE_ID.fullmatch(case_id) for case_id in ids)


def test_count_sets_the_number_of_cases(tmp_path: Path) -> None:
    assert len(_read(generate_corpus(tmp_path, count=500))["cases"]) == 500


def test_count_below_500_is_rejected_before_anything_is_written(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_COUNT$"):
        generate_corpus(tmp_path, count=499)
    assert list(tmp_path.iterdir()) == []


def test_corpus_covers_every_error_code_but_too_large_and_enough_accepts(
    corpus: dict[str, Any],
) -> None:
    outcomes = Counter(case["outcome"] for case in corpus["cases"])

    assert {code.value for code in WireErrorCode} - {"TOO_LARGE"} <= set(outcomes)
    assert outcomes["accept"] >= 50


def test_re_decoding_each_case_reproduces_its_outcome(corpus: dict[str, Any]) -> None:
    mismatches = [
        case["id"]
        for case in corpus["cases"]
        if _outcome(bytes.fromhex(case["hex"])) != case["outcome"]
    ]

    assert mismatches == []


def test_accepted_cases_re_encode_to_identical_bytes(corpus: dict[str, Any]) -> None:
    accepted = [bytes.fromhex(c["hex"]) for c in corpus["cases"] if c["outcome"] == "accept"]

    assert [data.hex() for data in accepted if encode(decode(data, CORPUS_LIMITS)) != data] == []
