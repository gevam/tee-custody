"""Development trust profile v2 (INC-2-API §16.1, §16.3; ADR 0012)."""

import hashlib
import re
from collections.abc import Sequence
from typing import Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from teecustody.wire import CanonicalValue, encode
from teecustody_sim.alterations import JsonValue
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import DEFAULT_TOKEN_MAX_AGE_S, SIM_HWMODEL, SIM_ISSUER
from teecustody_sim.keys import SignerKeyMaterial

_RSA_SIGNER_ALGORITHMS: Final = frozenset({"RSASSA_PSS_SHA256", "RSASSA_PKCS1V15_SHA256"})
_ECDSA_P256_ALGORITHM: Final = "ECDSA_P256_SHA256"
_MIN_RSA_BITS: Final = 2048
_RSA_PUBLIC_EXPONENT: Final = 65537
_PROFILE_VERSION: Final = 2
# `http://<loopback host>:<port>/jwks`, with no leading-zero port: exactly the strings Core's
# `new URL(value).href === value` rule accepts (INC-2-API §16.3). Port bounds are checked after.
_JWKS_URI: Final = re.compile(
    r"http://(?:127\.0\.0\.1|localhost|\[::1\]):([1-9][0-9]{0,4})/jwks", re.ASCII
)
_MAX_PORT: Final = 65535
_HTTP_DEFAULT_PORT: Final = 80


def launch_config_hashes(args: Sequence[str], env: Sequence[tuple[str, str]]) -> tuple[str, str]:
    args_value: list[CanonicalValue] = list(args)
    env_value: dict[str, CanonicalValue] = dict(env)
    return (
        hashlib.sha256(encode(args_value)).hexdigest(),
        hashlib.sha256(encode(env_value)).hexdigest(),
    )


def _canonical_key(spki_der: bytes) -> PublicKeyTypes:
    """Pass 1: the key `spki_der` holds, if `spki_der` is its canonical DER SPKI."""
    try:
        key = load_der_public_key(spki_der)
    except (ValueError, UnsupportedAlgorithm):
        raise ValueError("NONCANONICAL_SIGNER_SPKI") from None
    if key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) != spki_der:
        raise ValueError("NONCANONICAL_SIGNER_SPKI")
    return key


def _holder(key: PublicKeyTypes, canonical: bytes) -> tuple[object, ...]:
    """Pass 2 identity: the key material, so one holder under any encoding or `e` counts once."""
    if isinstance(key, rsa.RSAPublicKey):
        return ("RSA", key.public_numbers().n)
    if isinstance(key, ec.EllipticCurvePublicKey):
        point = key.public_numbers()
        return ("EC", key.curve.name, point.x, point.y)
    return ("OTHER", canonical)


def _fits_algorithm(key: PublicKeyTypes, algorithm: str) -> bool:
    """Pass 3: the key is one Core can count under its declared FACTS F-11 algorithm."""
    if algorithm in _RSA_SIGNER_ALGORITHMS:
        return (
            isinstance(key, rsa.RSAPublicKey)
            and key.key_size >= _MIN_RSA_BITS
            and key.public_numbers().e == _RSA_PUBLIC_EXPONENT
        )
    if algorithm == _ECDSA_P256_ALGORITHM:
        return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
    return False


def _signer_entries(signers: Sequence[SignerKeyMaterial]) -> list[JsonValue]:
    """One `{key_id, algorithm}` per signer, after validation passes 1-3 (amendment 2026-10-01b).

    Each pass walks every signer before the next pass starts, so the error names the first
    failing pass, not the first failing signer.
    """
    keyed = [(_canonical_key(signer.spki_der), signer) for signer in signers]
    holders = [_holder(key, signer.spki_der) for key, signer in keyed]
    if len(set(holders)) != len(holders):
        raise ValueError("DUPLICATE_SIGNER_KEY")
    if not all(_fits_algorithm(key, signer.algorithm) for key, signer in keyed):
        raise ValueError("UNSUPPORTED_SIGNER_KEY")
    return [
        {"key_id": hashlib.sha256(signer.spki_der).hexdigest(), "algorithm": signer.algorithm}
        for signer in signers
    ]


def _check_jwks_uri(jwks_uri: str) -> None:
    match = _JWKS_URI.fullmatch(jwks_uri)
    port = 0 if match is None else int(match[1])
    if not 1 <= port <= _MAX_PORT or port == _HTTP_DEFAULT_PORT:
        raise ValueError("INVALID_JWKS_URI")


def build_trust_profile(
    *,
    jwks_uri: str,
    expected_audience: str,
    launch: LaunchConfig,
    signers: Sequence[SignerKeyMaterial],
    signers_required: int,
    token_max_age_s: int = DEFAULT_TOKEN_MAX_AGE_S,
) -> dict[str, JsonValue]:
    _check_jwks_uri(jwks_uri)
    signer_keys = _signer_entries(signers)
    # `type(...) is int` also refuses `bool`, which `isinstance` would accept.
    if type(signers_required) is not int or not 1 <= signers_required <= len(signers):
        raise ValueError("INVALID_SIGNERS_REQUIRED")
    args_hash, env_hash = launch_config_hashes(launch.args, launch.env)
    return {
        "profile_version": _PROFILE_VERSION,
        "profile_kind": "development",
        "token_type": "OIDC",
        "issuer": SIM_ISSUER,
        "jwks_uri": jwks_uri,
        "expected_audience": expected_audience,
        "token_max_age_s": token_max_age_s,
        "allowed_hwmodels": [SIM_HWMODEL],
        "allowed_digests": [launch.image_digest],
        "signer_keys": signer_keys,
        "signers_required": signers_required,
        "expected_args_hash": args_hash,
        "expected_env_hash": env_hash,
    }
