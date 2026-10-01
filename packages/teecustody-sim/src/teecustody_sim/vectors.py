"""Cross-implementation vector suite and differential corpus generation."""

import hashlib
import json
import time
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from teecustody.wire import PROTO, CanonicalValue, encode
from teecustody_sim.alterations import JsonValue, NamedCase
from teecustody_sim.cases import NEGATIVE_CASES
from teecustody_sim.config import LaunchConfig
from teecustody_sim.constants import (
    DEFAULT_SIGNERS_REQUIRED,
    DEFAULT_TOKEN_MAX_AGE_S,
    SIM_ISSUER,
    SIM_TOKEN_TTL_S,
)
from teecustody_sim.keys import SimKeys
from teecustody_sim.profile import build_trust_profile
from teecustody_sim.token import TokenMinter

_LAUNCH: Final = LaunchConfig(
    "localhost/teecustody-vectors:1",
    "sha256:" + hashlib.sha256(b"teecustody-sim vector image").hexdigest(),
    ("/app/workload",),
    (("PYTHONUNBUFFERED", "1"),),
)
_AUDIENCE: Final = "https://vectors.teecustody.test/tee"
_JWKS_ORIGIN: Final = "http://127.0.0.1:8791"
_DISCOVERY_URL: Final = _JWKS_ORIGIN + "/.well-known/openid-configuration"
_JWKS_URL: Final = _JWKS_ORIGIN + "/jwks"
_DISCOVERY_DOCUMENT: Final[dict[str, JsonValue]] = {
    "claims_supported": [
        "aud",
        "dbgstat",
        "eat_nonce",
        "exp",
        "hwmodel",
        "iat",
        "iss",
        "nbf",
        "secboot",
        "submods",
        "swname",
    ],
    "id_token_signing_alg_values_supported": ["RS256"],
    "issuer": SIM_ISSUER,
    "jwks_uri": _JWKS_URL,
    "response_types_supported": ["id_token"],
    "scopes_supported": ["openid"],
    "subject_types_supported": ["public"],
}


def _json_text(value: JsonValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_bytes(value: JsonValue) -> bytes:
    return _json_text(value).encode()


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
        discovery_url=_DISCOVERY_URL,
        jwks_origin=_JWKS_ORIGIN,
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
        "production_profile_json": "{}",
        "http": {
            _DISCOVERY_URL: _json_bytes(_DISCOVERY_DOCUMENT),
            _JWKS_URL: _json_bytes(keys.issuer_jwks()),
        },
        "cases": _cases(minter, nonce, now),
    }
    path = out_dir / "attestation" / "suite.cbor"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encode(suite))
    return path


def generate_corpus(out_dir: Path, *, seed: int = 1, count: int = 512) -> Path:
    raise NotImplementedError("T-17")
