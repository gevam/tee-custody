"""T-06 criterion 8: one token source, no listener, no environment detection (spec §5.1, §11)."""

from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "teecustody"
POLICED_PACKAGES = ("attest", "channel")
FORBIDDEN = ("attestation_verifier_claims_token", ".bind(", ".listen(", "os.environ")


def _violations(root: Path) -> list[tuple[str, str]]:
    return [
        (str(path.relative_to(root)), needle)
        for package in POLICED_PACKAGES
        for path in sorted((root / package).rglob("*.py"))
        for needle in FORBIDDEN
        if needle in path.read_text(encoding="utf-8")
    ]


def test_policed_sources_exist() -> None:
    names = {path.name for package in POLICED_PACKAGES for path in (SRC / package).rglob("*.py")}
    assert {"launcher.py", "lifecycle.py", "nonce.py", "token.py", "identity.py"} <= names


def test_attest_and_channel_sources_contain_no_forbidden_construct() -> None:
    assert _violations(SRC) == []


@pytest.mark.parametrize("needle", FORBIDDEN)
def test_scan_detects_each_forbidden_construct(tmp_path: Path, needle: str) -> None:
    for package in POLICED_PACKAGES:
        (tmp_path / package / "sub").mkdir(parents=True)
    (tmp_path / "channel" / "sub" / "planted.py").write_text(f"x = 1  # {needle}\n")

    assert _violations(tmp_path) == [("channel/sub/planted.py", needle)]
