"""Simulator issuer and development signer keys."""

import base64
import errno
import hashlib
import json
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody_sim.alterations import JsonValue
from teecustody_sim.constants import DEV_SIGNER_ALGORITHM, JWS_ALG, MAX_SIGNERS

_RSA_BITS = 2048
_RSA_PUBLIC_EXPONENT = 65537
_PRIVATE_DIR_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_NOT_OWNER_BITS = 0o077
_PSS_SALT_32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _new_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_BITS)


def _check_signers_required(signers_required: int) -> None:
    if not 1 <= signers_required <= MAX_SIGNERS:
        raise ValueError("INVALID_SIGNERS_REQUIRED")


def _ensure_private_dir(path: Path) -> None:
    """Create `path` as an owner-only directory, or accept it only if it already is one."""
    try:
        path.mkdir(mode=_PRIVATE_DIR_MODE)
    except FileExistsError:
        status = os.lstat(path)
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) & _NOT_OWNER_BITS
        ):
            raise ValueError("INSECURE_KEY_FILE") from None
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, _PRIVATE_DIR_MODE)
    finally:
        os.close(fd)


def _read_owner_only_file(path: Path) -> bytes:
    """Read a regular file owned by this user with no group/other bits, through one fd."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        code = "INSECURE_KEY_FILE" if error.errno == errno.ELOOP else "INVALID_KEY_FILE"
        raise ValueError(code) from None
    try:
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("INVALID_KEY_FILE")
        if status.st_uid != os.getuid() or stat.S_IMODE(status.st_mode) & _NOT_OWNER_BITS:
            raise ValueError("INSECURE_KEY_FILE")
        with os.fdopen(fd, "rb", closefd=False) as file:
            return file.read()
    finally:
        os.close(fd)


def _load_key(path: Path) -> rsa.RSAPrivateKey:
    pem = _read_owner_only_file(path)
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise ValueError("INVALID_KEY_FILE") from None
    if (
        not isinstance(key, rsa.RSAPrivateKey)
        or key.key_size != _RSA_BITS
        or key.public_key().public_numbers().e != _RSA_PUBLIC_EXPONENT
    ):
        raise ValueError("INVALID_KEY_FILE")
    return key


def _load_or_create_key(path: Path) -> rsa.RSAPrivateKey:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, _PRIVATE_FILE_MODE)
    except FileExistsError:
        return _load_key(path)
    key = _new_rsa_key()
    with os.fdopen(fd, "wb") as file:
        os.fchmod(file.fileno(), _PRIVATE_FILE_MODE)
        file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return key


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class SignerKeyMaterial:
    key_id: str
    algorithm: str
    spki_der: bytes
    _private_key: rsa.RSAPrivateKey

    @classmethod
    def _from_private_key(cls, private_key: rsa.RSAPrivateKey) -> "SignerKeyMaterial":
        signer = cls()
        signer._private_key = private_key
        signer.algorithm = DEV_SIGNER_ALGORITHM
        signer.spki_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        signer.key_id = hashlib.sha256(signer.spki_der).hexdigest()
        return signer

    def __repr__(self) -> str:
        return f"SignerKeyMaterial(key_id={self.key_id})"

    def sign(self, payload: bytes) -> bytes:
        return self._private_key.sign(payload, _PSS_SALT_32, hashes.SHA256())


def _public_jwk(key: rsa.RSAPrivateKey) -> tuple[str, str, str]:
    """(`kid`, `n`, `e`): `kid` is the RFC 7638 thumbprint of the public key."""
    numbers = key.public_key().public_numbers()
    n, e = _b64url_uint(numbers.n), _b64url_uint(numbers.e)
    thumbprint_input = json.dumps(
        {"e": e, "kty": "RSA", "n": n}, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return _b64url(hashlib.sha256(thumbprint_input).digest()), n, e


class SimKeys:
    issuer_kid: str
    attacker_issuer_kid: str
    signers: tuple[SignerKeyMaterial, ...]
    unknown_signer: SignerKeyMaterial
    _issuer_key: rsa.RSAPrivateKey
    _issuer_n: str
    _issuer_e: str
    # T-29 attacker key (INC-2-API §16.3, L-1): signs only the `jwks_other_path*` cases.
    _attacker_key: rsa.RSAPrivateKey
    _attacker_n: str
    _attacker_e: str

    @classmethod
    def _from_private_keys(
        cls,
        issuer_key: rsa.RSAPrivateKey,
        signer_keys: tuple[rsa.RSAPrivateKey, ...],
        unknown_signer_key: rsa.RSAPrivateKey,
        attacker_key: rsa.RSAPrivateKey,
    ) -> "SimKeys":
        keys = cls()
        keys._issuer_key = issuer_key
        keys.signers = tuple(SignerKeyMaterial._from_private_key(key) for key in signer_keys)
        keys.unknown_signer = SignerKeyMaterial._from_private_key(unknown_signer_key)
        keys.issuer_kid, keys._issuer_n, keys._issuer_e = _public_jwk(issuer_key)
        keys._attacker_key = attacker_key
        keys.attacker_issuer_kid, keys._attacker_n, keys._attacker_e = _public_jwk(attacker_key)
        return keys

    def __repr__(self) -> str:
        return "SimKeys(<redacted>)"

    @classmethod
    def generate(cls, signers_required: int) -> "SimKeys":
        _check_signers_required(signers_required)
        return cls._from_private_keys(
            _new_rsa_key(),
            tuple(_new_rsa_key() for _ in range(signers_required)),
            _new_rsa_key(),
            _new_rsa_key(),
        )

    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> "SimKeys":
        _check_signers_required(signers_required)
        keys_dir = state_dir / "keys"
        _ensure_private_dir(state_dir)
        _ensure_private_dir(keys_dir)
        return cls._from_private_keys(
            _load_or_create_key(keys_dir / "issuer.pem"),
            tuple(
                _load_or_create_key(keys_dir / f"signer-{index}.pem")
                for index in range(1, signers_required + 1)
            ),
            _load_or_create_key(keys_dir / "unknown-signer.pem"),
            _load_or_create_key(keys_dir / "attacker-issuer.pem"),
        )

    def issuer_jwks(self) -> dict[str, JsonValue]:
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": JWS_ALG,
                    "use": "sig",
                    "kid": self.issuer_kid,
                    "n": self._issuer_n,
                    "e": self._issuer_e,
                }
            ]
        }

    def sign_jws(self, signing_input: bytes) -> bytes:
        return self._issuer_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    def attacker_jwks(self) -> dict[str, JsonValue]:
        """The attacker key under its own `kid` and under `issuer_kid` (rows 38, 39)."""
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "alg": JWS_ALG,
                    "use": "sig",
                    "kid": kid,
                    "n": self._attacker_n,
                    "e": self._attacker_e,
                }
                for kid in (self.attacker_issuer_kid, self.issuer_kid)
            ]
        }

    def sign_jws_attacker(self, signing_input: bytes) -> bytes:
        return self._attacker_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
