"""Cross-implementation vector suite and differential corpus generation."""

import base64
import hashlib
import json
import random
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from teecustody.wire import PROTO, CanonicalValue, DecodeLimits, WireError, decode, encode
from teecustody_sim.alterations import JsonValue, NamedCase
from teecustody_sim.cases import NEGATIVE_CASES
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import (
    DEFAULT_SIGNERS_REQUIRED,
    DEFAULT_TOKEN_MAX_AGE_S,
    JWS_ALG,
    SIM_TOKEN_TTL_S,
)
from teecustody_sim.issuer import ATTACKER_JWKS_PATH
from teecustody_sim.keys import SimKeys
from teecustody_sim.profile import build_trust_profile, launch_config_hashes
from teecustody_sim.token import TokenMinter

_LAUNCH: Final = LaunchConfig(
    "localhost/teecustody-vectors:1",
    "sha256:" + hashlib.sha256(b"teecustody-sim vector image").hexdigest(),
    ("/app/workload",),
    (("PYTHONUNBUFFERED", "1"),),
)
_AUDIENCE: Final = "https://vectors.teecustody.test/tee"
# INC-2-API §16.4: the `http` map holds JWKS URLs only, never a discovery URL, so a verifier that
# fetches discovery fails `valid`.
_JWKS_ORIGIN: Final = "http://127.0.0.1:8791"
_JWKS_URL: Final = _JWKS_ORIGIN + "/jwks"
_ATTACKER_JWKS_URL: Final = _JWKS_ORIGIN + ATTACKER_JWKS_PATH

# Production-shaped fixture (FACTS F-07, F-09 as amended). Its signer entries and JWKS key are
# throwaway fixture keys: the profile only has to look like production, never to trust anything.
_GOOGLE_ISSUER: Final = "https://confidentialcomputing.googleapis.com"
_GOOGLE_JWKS_URI: Final = (
    "https://www.googleapis.com"
    "/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
)
_PROFILE_VERSION: Final = 2
_PRODUCTION_HWMODELS: Final = ("GCP_AMD_SEV", "GCP_AMD_SEV_ES", "GCP_INTEL_TDX")
_FIXTURE_KID: Final = "production-fixture"
_FIXTURE_RSA_BITS: Final = 2048
_FIXTURE_RSA_PUBLIC_EXPONENT: Final = 65537


def _json_text(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_bytes(value: JsonValue) -> bytes:
    return _json_text(value).encode()


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _fixture_jwks() -> dict[str, JsonValue]:
    """A JWKS holding one fresh RSA-2048 public key; the private half is discarded."""
    numbers = (
        rsa.generate_private_key(
            public_exponent=_FIXTURE_RSA_PUBLIC_EXPONENT, key_size=_FIXTURE_RSA_BITS
        )
        .public_key()
        .public_numbers()
    )
    return {
        "keys": [
            {
                "kty": "RSA",
                "alg": JWS_ALG,
                "use": "sig",
                "kid": _FIXTURE_KID,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


def _production_profile() -> dict[str, JsonValue]:
    """The production-shaped v2 fixture (INC-2-API §16.1); no development anchor appears in it."""
    fixture_signers = SimKeys.generate(DEFAULT_SIGNERS_REQUIRED).signers
    args_hash, env_hash = launch_config_hashes(_LAUNCH.args, _LAUNCH.env)
    signer_keys: list[JsonValue] = [
        {"key_id": hashlib.sha256(signer.spki_der).hexdigest(), "algorithm": signer.algorithm}
        for signer in fixture_signers
    ]
    return {
        "profile_version": _PROFILE_VERSION,
        "profile_kind": "production",
        "token_type": "OIDC",
        "issuer": _GOOGLE_ISSUER,
        "jwks_uri": _GOOGLE_JWKS_URI,
        "expected_audience": _AUDIENCE,
        "token_max_age_s": DEFAULT_TOKEN_MAX_AGE_S,
        "allowed_hwmodels": list(_PRODUCTION_HWMODELS),
        "allowed_digests": [_LAUNCH.image_digest],
        "signer_keys": signer_keys,
        "signers_required": DEFAULT_SIGNERS_REQUIRED,
        "expected_args_hash": args_hash,
        "expected_env_hash": env_hash,
    }


def _cases(minter: TokenMinter, nonce: str, now: int) -> list[CanonicalValue]:
    """`valid`, then every §G negative case in catalog order, each minted by the simulator."""
    cases: list[CanonicalValue] = [
        {
            "id": "valid",
            "token": minter.mint(_AUDIENCE, [nonce], now),
            "expect": "accept",
            "check": "none",
            "error_code": "none",
            "altered": [],
            "debug_event": False,
        }
    ]
    for row in NEGATIVE_CASES:
        altered: list[CanonicalValue] = list(row.altered)
        cases.append(
            {
                "id": row.case_id,
                "token": minter.mint(_AUDIENCE, [nonce], now, NamedCase(row.case_id)),
                "expect": "reject",
                "check": row.check,
                "error_code": row.error_code,
                "altered": altered,
                "debug_event": row.debug_event,
            }
        )
    return cases


def generate_suite(out_dir: Path, *, now: int | None = None) -> Path:
    if now is None:
        now = int(time.time())
    keys = SimKeys.generate(DEFAULT_SIGNERS_REQUIRED)
    identity_public_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    nonce = hashlib.sha256(identity_public_key).hexdigest()
    minter = TokenMinter(
        keys, _LAUNCH, ttl_s=SIM_TOKEN_TTL_S, token_max_age_s=DEFAULT_TOKEN_MAX_AGE_S
    )
    profile = build_trust_profile(
        jwks_uri=_JWKS_URL,
        expected_audience=_AUDIENCE,
        launch=_LAUNCH,
        signers=keys.signers,
        signers_required=DEFAULT_SIGNERS_REQUIRED,
    )
    suite: dict[str, CanonicalValue] = {
        "suite": "teecustody-attestation-vectors",
        "suite_version": 1,
        "proto": PROTO,
        "generated_at": now,
        "verify_at_ms": now * 1000,
        "identity_public_key": identity_public_key,
        "profile_json": _json_text(profile),
        "production_profile_json": _json_text(_production_profile()),
        "http": {
            _JWKS_URL: _json_bytes(keys.issuer_jwks()),
            _ATTACKER_JWKS_URL: _json_bytes(keys.attacker_jwks()),
            _GOOGLE_JWKS_URI: _json_bytes(_fixture_jwks()),
        },
        "cases": _cases(minter, nonce, now),
    }
    path = out_dir / "attestation" / "suite.cbor"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(suite))
    return path


# Differential corpus (ADR 0010; API.md §F). `random.Random` is used for reproducibility only:
# the corpus is public test data, never key material.
_MIN_CORPUS_COUNT: Final = 500
_CORPUS_LIMITS: Final = DecodeLimits(max_bytes=1024, max_depth=8, max_items=256)
_MAX_VALUE_DEPTH: Final = 4
_MAX_CONTAINER_ITEMS: Final = 8
_MAX_STRING_LENGTH: Final = 8
_EDGE_INTEGERS: Final = (
    0,
    23,
    24,
    255,
    256,
    65535,
    65536,
    2**32 - 1,
    2**32,
    2**53 - 1,
    2**53,
    2**64 - 1,
    -1,
    -24,
    -25,
    -(2**64),
)
_TEXT_ALPHABET: Final = "az09 _-~\u00e9\u00df\u05d0\u4e2d\U0001f600"


def _random_int(rng: random.Random) -> int:
    if rng.random() < 0.5:
        return rng.choice(_EDGE_INTEGERS)
    return rng.randint(-(2**64), 2**64 - 1)


def _random_text(rng: random.Random) -> str:
    return "".join(rng.choice(_TEXT_ALPHABET) for _ in range(rng.randint(0, _MAX_STRING_LENGTH)))


def _random_value(rng: random.Random, depth: int) -> CanonicalValue:
    """A random canonical value; `depth` is this item's depth (top level 1, at most 4)."""
    kind = rng.choice(
        ("int", "bytes", "text", "simple", "array", "map")
        if depth < _MAX_VALUE_DEPTH
        else ("int", "bytes", "text", "simple")
    )
    if kind == "int":
        return _random_int(rng)
    if kind == "bytes":
        return rng.randbytes(rng.randint(0, _MAX_STRING_LENGTH))
    if kind == "text":
        return _random_text(rng)
    if kind == "simple":
        return rng.choice((None, False, True))
    size = rng.randint(0, _MAX_CONTAINER_ITEMS)
    if kind == "array":
        return [_random_value(rng, depth + 1) for _ in range(size)]
    return {_random_text(rng): _random_value(rng, depth + 1) for _ in range(size)}


def _flip_bit(rng: random.Random, data: bytes) -> bytes:
    position = rng.randrange(len(data))
    mutated = bytearray(data)
    mutated[position] ^= 1 << rng.randrange(8)
    return bytes(mutated)


def _insert_byte(rng: random.Random, data: bytes) -> bytes:
    position = rng.randint(0, len(data))
    return data[:position] + bytes([rng.randrange(256)]) + data[position:]


def _delete_byte(rng: random.Random, data: bytes) -> bytes:
    position = rng.randrange(len(data))
    return data[:position] + data[position + 1 :]


def _truncate(rng: random.Random, data: bytes) -> bytes:
    return data[: rng.randrange(len(data))]


def _replace_first_byte(rng: random.Random, data: bytes) -> bytes:
    return bytes([rng.randrange(256)]) + data[1:]


_MUTATIONS: Final[tuple[Callable[[random.Random, bytes], bytes], ...]] = (
    _flip_bit,
    _insert_byte,
    _delete_byte,
    _truncate,
    _replace_first_byte,
)


def _corpus_outcome(data: bytes) -> str:
    try:
        decode(data, _CORPUS_LIMITS)
    except WireError as error:
        return error.code.value
    return "accept"


def generate_corpus(out_dir: Path, *, seed: int = 1, count: int = 512) -> Path:
    if count < _MIN_CORPUS_COUNT:
        raise ValueError("INVALID_COUNT")
    rng = random.Random(seed)  # noqa: S311 - seeded for reproducible public test data
    cases: list[JsonValue] = []
    for index in range(count):
        encoded = encode(_random_value(rng, 1))
        mutated = rng.choice(_MUTATIONS)(rng, encoded)
        cases.append(
            {"id": f"m{index:04d}", "hex": mutated.hex(), "outcome": _corpus_outcome(mutated)}
        )
    document: dict[str, JsonValue] = {
        "format": "teecustody-cbor-differential-corpus",
        "version": 1,
        "seed": seed,
        "limits": {
            "max_bytes": _CORPUS_LIMITS.max_bytes,
            "max_depth": _CORPUS_LIMITS.max_depth,
            "max_items": _CORPUS_LIMITS.max_items,
        },
        "cases": cases,
    }
    path = out_dir / "wire" / "differential-corpus.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=None, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return path
