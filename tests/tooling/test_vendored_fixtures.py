"""T-37 A1: the vendored RFC 9180 vectors stay byte-for-byte and out of prettier's reach."""

import hashlib
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parents[1]
VECTORS = "fixtures/rfc9180/test-vectors.json"


def test_rfc9180_vectors_match_the_sha256_pinned_in_their_readme() -> None:
    readme = (TESTS / "fixtures" / "rfc9180" / "README.md").read_text()
    pinned = re.findall(r"^\| File SHA-256 +\| `([0-9a-f]{64})` +\|$", readme, re.MULTILINE)
    actual = hashlib.sha256((TESTS / VECTORS).read_bytes()).hexdigest()
    assert pinned == [actual]
    assert actual == "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6"


def test_prettierignore_holds_exactly_the_vendored_vectors() -> None:
    assert (TESTS / ".prettierignore").read_text() == f"{VECTORS}\n"
