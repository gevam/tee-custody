"""T-08 criterion 5: RFC 9180 CFRG known-answer tests (ADR 0011 C4; SR-14; spec §11).

The committed CFRG file is checked against the SHA-256 in its README before any case is used.
"""

import hashlib
import json
import re
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from teecustody.channel.hpke import AEAD_ID, KDF_ID, KEM_ID, open_base
from teecustody.secrets import Secret

FIXTURES = Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "rfc9180"
BASE_MODE = 0
AEAD_AES128_GCM = 0x0001

# (mode, kem_id, kdf_id, aead_id) -> pyhpke suite used for the library-side checks.
FILTERS: dict[str, tuple[tuple[int, int, int, int], CipherSuite]] = {
    "base-x25519-sha256-aes256gcm": (
        (BASE_MODE, KEM_ID, KDF_ID, AEAD_ID),
        CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES256_GCM),
    ),
    "rfc9180-a1-aes128gcm": (
        (BASE_MODE, KEM_ID, KDF_ID, AEAD_AES128_GCM),
        CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM),
    ),
}


def _readme_sha256() -> str:
    readme = (FIXTURES / "README.md").read_text()
    match = re.search(r"File SHA-256\s*\|\s*`([0-9a-f]{64})`", readme)
    assert match is not None, "README.md must record the file SHA-256"
    return match.group(1)


@cache
def _vectors() -> list[dict[str, Any]]:
    raw = (FIXTURES / "test-vectors.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _readme_sha256()
    vectors: list[dict[str, Any]] = json.loads(raw)
    return vectors


def _cases(name: str) -> list[dict[str, Any]]:
    (mode, kem_id, kdf_id, aead_id), _ = FILTERS[name]
    return [
        case
        for case in _vectors()
        if (case["mode"], case["kem_id"], case["kdf_id"], case["aead_id"])
        == (mode, kem_id, kdf_id, aead_id)
    ]


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def test_vector_file_matches_the_sha256_recorded_in_its_readme() -> None:
    raw = (FIXTURES / "test-vectors.json").read_bytes()

    assert hashlib.sha256(raw).hexdigest() == _readme_sha256()


@pytest.mark.parametrize("name", FILTERS)
def test_filtered_set_is_non_empty(name: str) -> None:
    assert _cases(name)


@pytest.mark.parametrize("name", FILTERS)
def test_library_receiver_matches_every_encryption_and_export(name: str) -> None:
    _, suite = FILTERS[name]
    cases = _cases(name)
    assert cases

    for case in cases:
        sender = suite.kem.derive_key_pair(_hex(case["ikmE"]))
        recipient = suite.kem.derive_key_pair(_hex(case["ikmR"]))
        assert sender.public_key.to_public_bytes() == _hex(case["pkEm"])
        assert recipient.public_key.to_public_bytes() == _hex(case["pkRm"])
        assert recipient.private_key.to_private_bytes() == _hex(case["skRm"])
        assert _hex(case["enc"]) == _hex(case["pkEm"])

        context = suite.create_recipient_context(
            _hex(case["enc"]), recipient.private_key, _hex(case["info"])
        )
        assert case["encryptions"]
        for encryption in case["encryptions"]:
            plaintext = context.open(_hex(encryption["ct"]), aad=_hex(encryption["aad"]))
            assert plaintext == _hex(encryption["pt"])
        assert case["exports"]
        for export in case["exports"]:
            exported = context.export(_hex(export["exporter_context"]), export["L"])
            assert exported == _hex(export["exported_value"])


def test_open_base_opens_the_first_encryption_of_every_aes256gcm_case() -> None:
    cases = _cases("base-x25519-sha256-aes256gcm")
    assert cases

    for case in cases:
        first = case["encryptions"][0]

        opened = open_base(
            Secret(_hex(case["skRm"])),
            _hex(case["enc"]),
            _hex(case["info"]),
            _hex(first["aad"]),
            _hex(first["ct"]),
        )

        assert opened.plaintext.reveal() == _hex(first["pt"])
