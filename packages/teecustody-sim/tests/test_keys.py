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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from teecustody_sim import DEV_SIGNER_ALGORITHM, JsonValue, SignerKeyMaterial, SimKeys

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


def _b64url_int(text: JsonValue) -> int:
    assert isinstance(text, str)
    return int.from_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)), "big")


def _jwk_entries(jwks: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    entries = jwks["keys"]
    assert isinstance(entries, list)
    assert all(isinstance(entry, dict) for entry in entries)
    return entries  # type: ignore[return-value]


def _rsa_public(jwk: dict[str, JsonValue]) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(_b64url_int(jwk["e"]), _b64url_int(jwk["n"])).public_key()


def test_attacker_jwks_lists_one_fresh_key_under_its_own_kid_and_the_issuer_kid(
    keys: SimKeys,
) -> None:
    """INC-2-API §16.3 (A-8, T-29): same-origin attacker key set; the issuer key is not in it."""
    jwks = keys.attacker_jwks()
    entries = _jwk_entries(jwks)
    issuer_jwk = _jwk_entries(keys.issuer_jwks())[0]

    assert set(jwks) == {"keys"}
    assert [entry["kid"] for entry in entries] == [keys.attacker_issuer_kid, keys.issuer_kid]
    for entry in entries:
        assert set(entry) == {"kty", "alg", "use", "kid", "n", "e"}
        assert (entry["kty"], entry["alg"], entry["use"], entry["e"]) == (
            "RSA",
            "RS256",
            "sig",
            "AQAB",
        )
        assert entry["n"] == entries[0]["n"]
        assert entry["n"] != issuer_jwk["n"]
    assert _rsa_public(entries[0]).key_size == 2048
    thumbprint_input = json.dumps(
        {"e": entries[0]["e"], "kty": "RSA", "n": entries[0]["n"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert keys.attacker_issuer_kid == _b64url(hashlib.sha256(thumbprint_input).digest())
    assert keys.attacker_issuer_kid != keys.issuer_kid


def test_sign_jws_attacker_is_rs256_under_the_attacker_key_only(keys: SimKeys) -> None:
    signing_input = b"header.payload"
    signature = keys.sign_jws_attacker(signing_input)
    attacker = _rsa_public(_jwk_entries(keys.attacker_jwks())[0])
    issuer = _rsa_public(_jwk_entries(keys.issuer_jwks())[0])

    attacker.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        issuer.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(InvalidSignature):
        attacker.verify(
            keys.sign_jws(signing_input), signing_input, padding.PKCS1v15(), hashes.SHA256()
        )


def test_generate_makes_a_fresh_attacker_key_each_time(keys: SimKeys) -> None:
    assert SimKeys.generate(2).attacker_issuer_kid != keys.attacker_issuer_kid


def test_repr_never_contains_the_attacker_key(keys: SimKeys) -> None:
    attacker_n = _jwk_entries(keys.attacker_jwks())[0]["n"]
    assert isinstance(attacker_n, str)
    for text in (repr(keys), str(keys)):
        assert attacker_n not in text
        assert keys.attacker_issuer_kid not in text
        assert "PRIVATE" not in text


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


KEY_FILES = (
    "issuer.pem",
    "signer-1.pem",
    "signer-2.pem",
    "unknown-signer.pem",
    "attacker-issuer.pem",
)


def _identity(keys: SimKeys) -> tuple[str, tuple[str, ...], str, str]:
    return (
        keys.issuer_kid,
        tuple(signer.key_id for signer in keys.signers),
        keys.unknown_signer.key_id,
        keys.attacker_issuer_kid,
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
    assert grown.attacker_issuer_kid == created.attacker_issuer_kid
    assert _mode(tmp_path / "keys" / "signer-3.pem") == 0o600


def test_attacker_key_is_created_when_absent_as_pkcs8_owner_only(tmp_path: Path) -> None:
    """L-1 (D-047): an INC-1 state directory gains its attacker key on the next load."""
    created = SimKeys.load_or_create(tmp_path, 2)
    attacker_file = tmp_path / "keys" / "attacker-issuer.pem"
    attacker_file.unlink()

    reloaded = SimKeys.load_or_create(tmp_path, 2)

    assert reloaded.issuer_kid == created.issuer_kid
    assert reloaded.attacker_issuer_kid != created.attacker_issuer_kid
    assert _mode(attacker_file) == 0o600
    assert attacker_file.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----\n")
    loaded = serialization.load_pem_private_key(attacker_file.read_bytes(), password=None)
    assert isinstance(loaded, rsa.RSAPrivateKey)
    assert (
        _b64url(loaded.public_key().public_numbers().n.to_bytes(256, "big"))
        == _jwk_entries(reloaded.attacker_jwks())[0]["n"]
    )


def test_two_state_directories_get_different_attacker_keys(tmp_path: Path) -> None:
    """S6 (L-1): the attacker key is generated per state directory, never shared or committed."""
    first = SimKeys.load_or_create(tmp_path / "a", 2)
    second = SimKeys.load_or_create(tmp_path / "b", 2)

    assert first.attacker_issuer_kid != second.attacker_issuer_kid
    assert (tmp_path / "a" / "keys" / "attacker-issuer.pem").read_bytes() != (
        tmp_path / "b" / "keys" / "attacker-issuer.pem"
    ).read_bytes()


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
    [(name, 0o644) for name in KEY_FILES]
    + [("issuer.pem", m) for m in (0o640, 0o604, 0o660, 0o620, 0o602, 0o610, 0o601)],
)
def test_load_or_create_rejects_a_key_file_accessible_beyond_its_owner(
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


def _encrypted_pem() -> bytes:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"test-only-passphrase"),
    )


def _replace_with_symlink_to_valid_key(path: Path) -> None:
    target = path.with_name("elsewhere.pem")
    path.rename(target)
    path.symlink_to(target)


def _replace_with_dangling_symlink(path: Path) -> None:
    path.unlink()
    path.symlink_to(path.with_name("missing.pem"))


def _replace_with_directory(path: Path) -> None:
    path.unlink()
    path.mkdir(mode=0o700)


def _replace_with_fifo(path: Path) -> None:
    path.unlink()
    os.mkfifo(path, 0o600)


def _replace_with_encrypted_pem(path: Path) -> None:
    path.write_bytes(_encrypted_pem())


def _make_unreadable(path: Path) -> None:
    path.chmod(0o000)


@pytest.mark.parametrize(
    "replace",
    [_replace_with_symlink_to_valid_key, _replace_with_dangling_symlink],
    ids=["symlink", "dangling-symlink"],
)
def test_load_or_create_rejects_a_key_path_that_is_a_symlink(
    tmp_path: Path, key_files: dict[str, bytes], replace: Callable[[Path], None]
) -> None:
    _seed_state(tmp_path, key_files)
    replace(tmp_path / "keys" / "signer-1.pem")

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path, 2)


@pytest.mark.parametrize(
    "replace",
    [_replace_with_directory, _replace_with_fifo, _replace_with_encrypted_pem, _make_unreadable],
    ids=["directory", "fifo", "encrypted-pem", "unreadable"],
)
def test_load_or_create_rejects_a_key_path_that_is_not_a_plain_unencrypted_key_file(
    tmp_path: Path, key_files: dict[str, bytes], replace: Callable[[Path], None]
) -> None:
    _seed_state(tmp_path, key_files)
    replace(tmp_path / "keys" / "signer-1.pem")

    with pytest.raises(ValueError, match=r"^INVALID_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path, 2)


def test_load_or_create_rejects_a_key_file_owned_by_another_user(
    tmp_path: Path, key_files: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_state(tmp_path, key_files)
    real_fstat = os.fstat

    def fstat_owned_by_someone_else(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        fields = list(st[:10])
        fields[stat.ST_UID] = st.st_uid + 1
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", fstat_owned_by_someone_else)

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path, 2)


def _keys_dir_mode_0755(state_dir: Path) -> None:
    (state_dir / "keys").chmod(0o755)


def _keys_dir_mode_0770(state_dir: Path) -> None:
    (state_dir / "keys").chmod(0o770)


def _state_dir_mode_0755(state_dir: Path) -> None:
    state_dir.chmod(0o755)


def _keys_dir_is_a_symlink(state_dir: Path) -> None:
    (state_dir / "keys").rename(state_dir / "real-keys")
    (state_dir / "keys").symlink_to(state_dir / "real-keys")


def _keys_dir_is_a_file(state_dir: Path) -> None:
    for path in (state_dir / "keys").iterdir():
        path.unlink()
    (state_dir / "keys").rmdir()
    (state_dir / "keys").write_bytes(b"")


@pytest.mark.parametrize(
    "tamper",
    [
        _keys_dir_mode_0755,
        _keys_dir_mode_0770,
        _state_dir_mode_0755,
        _keys_dir_is_a_symlink,
        _keys_dir_is_a_file,
    ],
    ids=["keys-0755", "keys-0770", "state-0755", "keys-symlink", "keys-file"],
)
def test_load_or_create_rejects_an_existing_directory_that_is_not_owner_only(
    tmp_path: Path, key_files: dict[str, bytes], tamper: Callable[[Path], None]
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    _seed_state(state_dir, key_files)
    tamper(state_dir)
    modes_before = {p: os.lstat(p).st_mode for p in (state_dir, state_dir / "keys")}

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(state_dir, 2)
    assert {p: os.lstat(p).st_mode for p in modes_before} == modes_before


def test_load_or_create_rejects_a_state_dir_that_is_a_symlink(
    tmp_path: Path, key_files: dict[str, bytes]
) -> None:
    real = tmp_path / "real-state"
    real.mkdir(mode=0o700)
    _seed_state(real, key_files)
    (tmp_path / "state").symlink_to(real)

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path / "state", 2)


def test_load_or_create_rejects_directories_owned_by_another_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "state").mkdir(mode=0o700)
    real_getuid = os.getuid
    monkeypatch.setattr(os, "getuid", lambda: real_getuid() + 1)

    with pytest.raises(ValueError, match=r"^INSECURE_KEY_FILE$"):
        SimKeys.load_or_create(tmp_path / "state", 2)
    assert not (tmp_path / "state" / "keys").exists()


@pytest.mark.parametrize(
    ("cls", "public"),
    [
        (
            SimKeys,
            {
                "generate",
                "load_or_create",
                "issuer_jwks",
                "sign_jws",
                "attacker_jwks",
                "sign_jws_attacker",
            },
        ),
        (SignerKeyMaterial, {"sign"}),
    ],
)
def test_key_classes_expose_only_the_api_surface(cls: type, public: set[str]) -> None:
    assert {name for name in vars(cls) if not name.startswith("_")} == public
    assert "__init__" not in vars(cls)
