"""Simulator issuer and development signer keys."""

from pathlib import Path

from teecustody_sim.alterations import JsonValue


class SignerKeyMaterial:
    key_id: str
    algorithm: str
    spki_der: bytes

    def sign(self, payload: bytes) -> bytes:
        raise NotImplementedError


class SimKeys:
    issuer_kid: str
    signers: tuple[SignerKeyMaterial, ...]
    unknown_signer: SignerKeyMaterial

    @classmethod
    def generate(cls, signers_required: int) -> "SimKeys":
        raise NotImplementedError

    @classmethod
    def load_or_create(cls, state_dir: Path, signers_required: int) -> "SimKeys":
        raise NotImplementedError

    def issuer_jwks(self) -> dict[str, JsonValue]:
        raise NotImplementedError

    def sign_jws(self, signing_input: bytes) -> bytes:
        raise NotImplementedError
