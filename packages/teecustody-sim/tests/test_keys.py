"""T-07: simulator issuer key and development signer keys (API.md §C keys.py; SR-7)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from teecustody_sim import DEV_SIGNER_ALGORITHM, SimKeys

PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi")
HEX64 = frozenset("0123456789abcdef")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def keys() -> SimKeys:
    return SimKeys.generate(2)


def test_generate_makes_requested_signers_and_an_unknown_signer_keyed_by_spki_sha256(
    keys: SimKeys,
) -> None:
    every = [*keys.signers, keys.unknown_signer]
    assert len(keys.signers) == 2
    key_ids = [signer.key_id for signer in every]
    assert len(set(key_ids)) == 3
    for signer in every:
        assert len(signer.key_id) == 64
        assert set(signer.key_id) <= HEX64
        assert signer.key_id == hashlib.sha256(signer.spki_der).hexdigest()
        assert signer.algorithm == DEV_SIGNER_ALGORITHM
        public = serialization.load_der_public_key(signer.spki_der)
        assert (
            public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            == signer.spki_der
        )


def test_issuer_jwks_is_one_public_rs256_key_with_rfc7638_thumbprint_kid(keys: SimKeys) -> None:
    jwks = keys.issuer_jwks()
    assert set(jwks) == {"keys"}
    entries = jwks["keys"]
    assert isinstance(entries, list)
    assert len(entries) == 1
    jwk = entries[0]
    assert isinstance(jwk, dict)
    assert set(jwk) == {"kty", "alg", "use", "kid", "n", "e"}
    for member in PRIVATE_JWK_MEMBERS:
        assert member not in jwk
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["e"] == "AQAB"
    n = jwk["n"]
    assert isinstance(n, str)
    assert "=" not in n
    assert len(base64.urlsafe_b64decode(n + "=" * (-len(n) % 4))) == 256
    thumbprint_input = json.dumps(
        {"e": jwk["e"], "kty": "RSA", "n": n}, sort_keys=True, separators=(",", ":")
    ).encode()
    assert keys.issuer_kid == _b64url(hashlib.sha256(thumbprint_input).digest())
    assert jwk["kid"] == keys.issuer_kid


def test_reprs_expose_no_key_material(keys: SimKeys) -> None:
    assert repr(keys) == "SimKeys(<redacted>)"
    assert str(keys) == "SimKeys(<redacted>)"
    for signer in [*keys.signers, keys.unknown_signer]:
        assert repr(signer) == f"SignerKeyMaterial(key_id={signer.key_id})"
        assert "PRIVATE" not in repr(signer)


@pytest.mark.parametrize("count", [0, -1, 17])
def test_generate_rejects_signer_count_out_of_range(count: int) -> None:
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        SimKeys.generate(count)


KEY_FILES = ("issuer.pem", "signer-1.pem", "signer-2.pem", "unknown-signer.pem")


def _identity(keys: SimKeys) -> tuple[str, tuple[str, ...], str]:
    return (
        keys.issuer_kid,
        tuple(signer.key_id for signer in keys.signers),
        keys.unknown_signer.key_id,
    )


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def permissive_umask() -> Iterator[None]:
    previous = os.umask(0)
    try:
        yield
    finally:
        os.umask(previous)


def test_load_or_create_twice_loads_the_same_keys_from_owner_only_files(
    tmp_path: Path, permissive_umask: None
) -> None:
    state_dir = tmp_path / "state"

    created = SimKeys.load_or_create(state_dir, 2)
    loaded = SimKeys.load_or_create(state_dir, 2)

    assert _identity(loaded) == _identity(created)
    assert _mode(state_dir) == 0o700
    assert _mode(state_dir / "keys") == 0o700
    assert sorted(p.name for p in (state_dir / "keys").iterdir()) == sorted(KEY_FILES)
    for name in KEY_FILES:
        path = state_dir / "keys" / name
        assert _mode(path) == 0o600
        assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----\n")


def test_load_or_create_generates_only_missing_key_files(tmp_path: Path) -> None:
    created = SimKeys.load_or_create(tmp_path, 2)
    (tmp_path / "keys" / "signer-2.pem").unlink()

    grown = SimKeys.load_or_create(tmp_path, 3)

    assert grown.issuer_kid == created.issuer_kid
    assert grown.signers[0].key_id == created.signers[0].key_id
    assert grown.signers[1].key_id != created.signers[1].key_id
    assert len(grown.signers) == 3
    assert grown.unknown_signer.key_id == created.unknown_signer.key_id
    assert _mode(tmp_path / "keys" / "signer-3.pem") == 0o600


@pytest.fixture(scope="module")
def key_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    state_dir = tmp_path_factory.mktemp("key-files")
    SimKeys.load_or_create(state_dir, 2)
    return {name: (state_dir / "keys" / name).read_bytes() for name in KEY_FILES}


def _seed_state(state_dir: Path, key_files: dict[str, bytes]) -> None:
    keys_dir = state_dir / "keys"
    keys_dir.mkdir(mode=0o700)
    for name, content in key_files.items():
        (keys_dir / name).write_bytes(content)
        (keys_dir / name).chmod(0o600)


@pytest.mark.parametrize(
    ("name", "mode"),
    [(name, 0o644) for name in KEY_FILES] + [("issuer.pem", m) for m in (0o640, 0o604, 0o660)],
)
def test_load_or_create_rejects_a_key_file_readable_beyond_its_owner(
    tmp_path: Path, key_files: dict[str, bytes], name: str, mode: int
) -> None:
    _seed_state(tmp_path, key_files)
    SimKeys.load_or_create(tmp_path, 2)
    (tmp_path / "keys" / name).chmod(mode)

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path, 2)


@pytest.mark.parametrize("count", [0, 17])
def test_load_or_create_rejects_signer_count_before_touching_disk(
    tmp_path: Path, count: int
) -> None:
    state_dir = tmp_path / "state"
    with pytest.raises(ValueError, match=r"^INVALID_SIGNERS_REQUIRED$"):
        SimKeys.load_or_create(state_dir, count)
    assert not state_dir.exists()


def _pem(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(lambda: b"not a pem file\n", id="garbage"),
        pytest.param(lambda: _pem(ec.generate_private_key(ec.SECP256R1())), id="ec-p256"),
        pytest.param(
            lambda: _pem(rsa.generate_private_key(public_exponent=65537, key_size=1024)),  # noqa: S505
            id="rsa-1024",
        ),
        pytest.param(
            lambda: _pem(rsa.generate_private_key(public_exponent=3, key_size=2048)),
            id="rsa-e3",
        ),
    ],
)
def test_load_or_create_rejects_a_key_file_that_is_not_rsa_2048_e65537(
    tmp_path: Path, key_files: dict[str, bytes], content: Callable[[], bytes]
) -> None:
    _seed_state(tmp_path, {**key_files, "signer-2.pem": content()})

    with pytest.raises(ValueError, match=r"^INVALID_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path, 2)
