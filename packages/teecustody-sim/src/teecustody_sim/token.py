"""Simulator token minting and alterations."""

import base64
import json
from collections.abc import Callable, Sequence
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody_sim.alterations import Alteration, JsonValue
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import (
    DBGSTAT_DISABLED,
    JWS_ALG,
    SIM_HWMODEL,
    SIM_ISSUER,
    SUPPORT_ATTRIBUTES,
    SWNAME,
)
from teecustody_sim.keys import SignerKeyMaterial, SimKeys

_PSS_SALT_32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_bytes(value: JsonValue) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _docker_reference(image_reference: str) -> str:
    name = image_reference.split("@", 1)[0]
    repository, _, last_segment = name.rpartition("/")
    last_segment = last_segment.split(":", 1)[0]
    return f"{repository}/{last_segment}" if repository else last_segment


def image_signature_payload(image_reference: str, image_digest: str) -> bytes:
    return _json_bytes(
        {
            "critical": {
                "identity": {"docker-reference": _docker_reference(image_reference)},
                "image": {"docker-manifest-digest": image_digest},
                "type": "cosign container image signature",
            },
            "optional": None,
        }
    )


def _signature_verifies(signer: SignerKeyMaterial, signature: bytes, payload: bytes) -> bool:
    public_key = serialization.load_der_public_key(signer.spki_der)
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    try:
        public_key.verify(signature, payload, _PSS_SALT_32, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def _verified_image_signatures(
    signers: Sequence[SignerKeyMaterial], payload: bytes
) -> list[JsonValue]:
    """Sign with every signer; list only signatures that verify (Google emulation, D-016/T-22)."""
    entries: list[JsonValue] = []
    for signer in signers:
        signature = signer.sign(payload)
        if _signature_verifies(signer, signature, payload):
            entries.append(_image_signature_entry(signer, signature))
    return entries


def _image_signature_entry(signer: SignerKeyMaterial, signature: bytes) -> JsonValue:
    return {
        "key_id": signer.key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signature_algorithm": signer.algorithm,
    }


def frame_jws(header: bytes, payload: bytes, sign: Callable[[bytes], bytes]) -> str:
    signing_input = f"{_b64url(header)}.{_b64url(payload)}"
    return f"{signing_input}.{_b64url(sign(signing_input.encode('ascii')))}"


def parse_alteration(kind: Literal["alter", "drop", "case"], text: str) -> Alteration:
    raise NotImplementedError("T-07")


class TokenMinter:
    def __init__(
        self,
        keys: SimKeys,
        launch: LaunchConfig,
        *,
        issuer: str = SIM_ISSUER,
        ttl_s: int,
        token_max_age_s: int,
    ) -> None:
        self._keys = keys
        self._launch = launch
        self._issuer = issuer
        self._ttl_s = ttl_s
        self._token_max_age_s = token_max_age_s

    def claims(self, audience: str, nonces: Sequence[str], now: int) -> dict[str, JsonValue]:
        launch = self._launch
        payload = image_signature_payload(launch.image_reference, launch.image_digest)
        claims: dict[str, JsonValue] = {
            "iss": self._issuer,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + self._ttl_s,
            "eat_nonce": nonces[0],
            "hwmodel": SIM_HWMODEL,
            "swname": SWNAME,
            "secboot": True,
            "dbgstat": DBGSTAT_DISABLED,
            "submods": {
                "confidential_space": {"support_attributes": list(SUPPORT_ATTRIBUTES)},
                "container": {
                    "image_reference": launch.image_reference,
                    "image_digest": launch.image_digest,
                    "image_signatures": _verified_image_signatures(self._keys.signers, payload),
                    "args": list(launch.args),
                    "env": dict(launch.env),
                },
            },
        }
        return claims

    def mint(
        self,
        audience: str,
        nonces: Sequence[str],
        now: int,
        alteration: Alteration | None = None,
    ) -> str:
        header: JsonValue = {"alg": JWS_ALG, "kid": self._keys.issuer_kid, "typ": "JWT"}
        return frame_jws(
            _json_bytes(header),
            _json_bytes(self.claims(audience, nonces, now)),
            self._keys.sign_jws,
        )
