"""Simulator issuer and development signer keys."""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from teecustody_sim.alterations import JsonValue
from teecustody_sim.constants import DEV_SIGNER_ALGORITHM, JWS_ALG, MAX_SIGNERS

_RSA_BITS = 2048
_RSA_PUBLIC_EXPONENT = 65537


def _new_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_BITS)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


class SignerKeyMaterial:
    key_id: str
    algorithm: str
    spki_der: bytes

    def __init__(self, private_key: rsa.RSAPrivateKey) -> None:
        self._private_key = private_key
        self.algorithm = DEV_SIGNER_ALGORITHM
        self.spki_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.key_id = hashlib.sha256(self.spki_der).hexdigest()

    def __repr__(self) -> str:
        return f"SignerKeyMaterial(key_id={self.key_id})"

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError("T-07")


class SimKeys:
    issuer_kid: str
    signers: tuple[SignerKeyMaterial, ...]
    unknown_signer: SignerKeyMaterial

    def __init__(
        self,
        issuer_key: rsa.RSAPrivateKey,
        signer_keys: tuple[rsa.RSAPrivateKey, ...],
        unknown_signer_key: rsa.RSAPrivateKey,
    ) -> None:
        self._issuer_key = issuer_key
        self.signers = tuple(SignerKeyMaterial(key) for key in signer_keys)
        self.unknown_signer = SignerKeyMaterial(unknown_signer_key)
        numbers = issuer_key.public_key().public_numbers()
        self._issuer_n = _b64url_uint(numbers.n)
        self._issuer_e = _b64url_uint(numbers.e)
        thumbprint_input = json.dumps(
            {"e": self._issuer_e, "kty": "RSA", "n": self._issuer_n},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        self.issuer_kid = _b64url(hashlib.sha256(thumbprint_input).digest())

    def __repr__(self) -> str:
        return "SimKeys(<redacted>)"

    @classmethod
    def generate(cls, signers_required: int) -> "SimKeys":
        if not 1 <= signers_required <= MAX_SIGNERS:
            raise ValueError("INVALID_SIGNERS_REQUIRED")
        return cls(
            _new_rsa_key(),
            tuple(_new_rsa_key() for _ in range(signers_required)),
            _new_rsa_key(),
        )

    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> "SimKeys":
        raise NotImplementedError("T-07")

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
        raise NotImplementedError("T-07")
