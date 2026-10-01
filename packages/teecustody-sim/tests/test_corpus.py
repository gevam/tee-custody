"""T-17: differential CBOR corpus generator (API.md §C vectors.py, §F; ADR 0010; SR-3)."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

import teecustody_sim.vectors
from teecustody.wire import CanonicalValue, DecodeLimits, WireError, WireErrorCode, decode, encode
from teecustody_sim import generate_corpus

CORPUS_LIMITS = DecodeLimits(max_bytes=1024, max_depth=8, max_items=256)
CASE_ID = re.compile(r"m[0-9]{4}")
HEX = re.compile(r"(?:[0-9a-f]{2})*")
EDGE_INTEGERS = frozenset(
    {0, 23, 24, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**53 - 1, 2**53, 2**64 - 1}
    | {-1, -24, -25, -(2**64)}
)
MUTATION_KINDS = ("bit_flip", "insert", "delete", "truncate", "first_byte")


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


class Traced:
    """One corpus case with the canonical encoding it was mutated from."""

    def __init__(self, value: CanonicalValue, original: bytes, case: dict[str, Any]) -> None:
        self.value = value
        self.original = original
        self.mutated = bytes.fromhex(case["hex"])
        self.outcome = case["outcome"]


@pytest.fixture(scope="module")
def traced(tmp_path_factory: pytest.TempPathFactory) -> list[Traced]:
    """Generate the default corpus while recording every value the generator encodes."""
    encoded: list[tuple[CanonicalValue, bytes]] = []
    real_encode = teecustody_sim.vectors.encode

    def spy(value: CanonicalValue) -> bytes:
        data = real_encode(value)
        encoded.append((value, data))
        return data

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(teecustody_sim.vectors, "encode", spy)
        cases = _read(generate_corpus(tmp_path_factory.mktemp("traced")))["cases"]
    assert len(encoded) == len(cases)
    return [Traced(v, data, case) for (v, data), case in zip(encoded, cases, strict=True)]


def _deletions(data: bytes) -> set[bytes]:
    return {data[:index] + data[index + 1 :] for index in range(len(data))}


def _unambiguous_kind(original: bytes, mutated: bytes) -> str | None:
    """The mutation kind only one of the five could have produced, if any."""
    if len(mutated) == len(original) + 1 and original in _deletions(mutated):
        return "insert"
    if len(mutated) == len(original) - 1 and not original.startswith(mutated):
        return "delete" if mutated in _deletions(original) else None
    if len(mutated) <= len(original) - 2 and original.startswith(mutated):
        return "truncate"
    if len(mutated) != len(original) or mutated == original:
        return None
    differing = [i for i, (a, b) in enumerate(zip(original, mutated, strict=True)) if a != b]
    flipped_bits = (original[differing[0]] ^ mutated[differing[0]]).bit_count()
    if differing == [0] and flipped_bits >= 2:
        return "first_byte"
    if len(differing) == 1 and differing[0] > 0 and flipped_bits == 1:
        return "bit_flip"
    return None


def _explained(original: bytes, mutated: bytes) -> bool:
    """True iff one of the five mutation kinds can turn `original` into `mutated`."""
    if len(mutated) == len(original) + 1:
        return original in _deletions(mutated)
    if len(mutated) < len(original):
        return original.startswith(mutated) or mutated in _deletions(original)
    if len(mutated) != len(original):
        return False
    if mutated[1:] == original[1:]:
        return True
    differing = [i for i, (a, b) in enumerate(zip(original, mutated, strict=True)) if a != b]
    return len(differing) == 1 and (original[differing[0]] ^ mutated[differing[0]]).bit_count() == 1


def _walk(value: CanonicalValue) -> list[CanonicalValue]:
    items: list[CanonicalValue] = [value]
    if isinstance(value, list):
        for item in value:
            items.extend(_walk(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            items.extend((key, *_walk(item)))
    return items


def _depth(value: CanonicalValue) -> int:
    """Rule-5 depth: the item itself is 1; map keys and values sit one level below their map."""
    if isinstance(value, list):
        return 1 + max(map(_depth, value), default=0)
    if isinstance(value, dict):
        return 1 + max((max(1, _depth(item)) for item in value.values()), default=0)
    return 1


def _ints(value: CanonicalValue) -> list[int]:
    return [item for item in _walk(value) if type(item) is int]


def _texts(value: CanonicalValue) -> list[str]:
    return [item for item in _walk(value) if isinstance(item, str)]


def _accepted_values(traced: list[Traced]) -> list[CanonicalValue]:
    return [decode(case.mutated, CORPUS_LIMITS) for case in traced if case.outcome == "accept"]


def test_every_case_is_one_mutation_of_its_canonical_original(traced: list[Traced]) -> None:
    assert all(encode(case.value) == case.original for case in traced)
    assert [i for i, case in enumerate(traced) if not _explained(case.original, case.mutated)] == []


def test_every_mutation_kind_leaves_a_trace(traced: list[Traced]) -> None:
    kinds = Counter(_unambiguous_kind(case.original, case.mutated) for case in traced)

    assert {kind: kinds[kind] > 0 for kind in MUTATION_KINDS} == dict.fromkeys(MUTATION_KINDS, True)


def test_generated_values_stay_within_the_documented_shape(traced: list[Traced]) -> None:
    values = [case.value for case in traced]

    assert max(map(_depth, values)) == 4
    containers = [item for v in values for item in _walk(v) if isinstance(item, list | dict)]
    assert max(map(len, containers)) == 8
    assert max(len(item) for v in values for item in _walk(v) if isinstance(item, bytes)) <= 8


def test_generated_ints_are_edge_values_and_uniform_draws(traced: list[Traced]) -> None:
    ints = {item for case in traced for item in _ints(case.value)}

    assert ints >= EDGE_INTEGERS
    assert len(ints - EDGE_INTEGERS) >= 50


def test_accepted_cases_include_a_map(traced: list[Traced]) -> None:
    assert any(isinstance(item, dict) for v in _accepted_values(traced) for item in _walk(v))


def test_accepted_cases_include_non_ascii_text(traced: list[Traced]) -> None:
    texts = [text for v in _accepted_values(traced) for text in _texts(v)]

    assert any(not text.isascii() for text in texts)


def test_accepted_cases_include_an_int_beyond_2_pow_53(traced: list[Traced]) -> None:
    assert any(item > 2**53 for v in _accepted_values(traced) for item in _ints(v))


def test_accepted_cases_include_depth_four_nesting(traced: list[Traced]) -> None:
    assert max(map(_depth, _accepted_values(traced))) == 4
