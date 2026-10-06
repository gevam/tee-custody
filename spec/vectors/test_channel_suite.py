"""INC-2 channel vector suite conformance, Python side (spec/wire/channel-vectors.cddl).

NFR-7, SR-3, SR-14. The approved CDDL hashes and the named-case catalog below are transcribed
from docs/INC-2-API.md sections 2 and 3 and are deliberately not imported from `teecustody_sim`:
the suite is checked against the specification, not its generator. API-TL TL-9 fixes which arrays
this harness checks; the TypeScript side checks the rest.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

WIRE_DIR = Path(__file__).parent.parent / "wire"

# SHA-256 of the approved INC-2-API §3.1 / §3.2 code-block bodies (D-041), each ending in one "\n".
APPROVED_CDDL_SHA256 = {
    "channel.cddl": "1dea64fba5e52b4a105780ac4a1049e9827836050f05615dac52ce93d4c783ca",
    "channel-vectors.cddl": "7f8518d76673ade456b8c685a3336b0d57c4746ecf5f87818ee0f2110ca6658e",
}


@pytest.mark.parametrize(("name", "sha256"), sorted(APPROVED_CDDL_SHA256.items()))
def test_cddl_matches_approved_text(name: str, sha256: str) -> None:
    assert hashlib.sha256((WIRE_DIR / name).read_bytes()).hexdigest() == sha256
