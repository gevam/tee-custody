"""Simulator token minting and alterations."""

import base64
import hashlib
import json
import re
from collections.abc import Callable, Sequence
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from teecustody_sim.alterations import (
    Alteration,
    AlterClaim,
    ClaimPath,
    DropClaim,
    JsonValue,
    NamedCase,
)
from teecustody_sim.cases import NEGATIVE_CASES
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

_MAX_NONCES = 6
_MIN_NONCE_BYTES = 10
_MAX_NONCE_BYTES = 74
_PSS_SALT_32 = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
_IMAGE_SIGNATURES: ClaimPath = ("submods", "container", "image_signatures")
_WRONG_NONCE = hashlib.sha256(b"teecustody-sim wrong nonce").hexdigest()
_UNKNOWN_DIGEST = "sha256:" + hashlib.sha256(b"teecustody-sim unknown image").hexdigest()
_MISMATCHED_SIGNATURE_ALGORITHM = "RSASSA_PKCS1V15_SHA256"
_CLAIM_PATH = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*")
_CASE_IDS = frozenset(case.case_id for case in NEGATIVE_CASES)
_CORRUPTED_SIGNATURE_CASES = frozenset({"token_signature_corrupted", "debug_bad_signature"})

type _Sign = Callable[[bytes], bytes]
type _SignatureEntry = dict[str, JsonValue]


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


def _check_nonces(nonces: Sequence[str]) -> None:
    """FACTS F-03: at most 6 nonces, each 10 to 74 bytes inclusive."""
    if len(nonces) > _MAX_NONCES:
        raise ValueError("INVALID_NONCE")
    for nonce in nonces:
        try:
            size = len(nonce.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("INVALID_NONCE") from None
        if not _MIN_NONCE_BYTES <= size <= _MAX_NONCE_BYTES:
            raise ValueError("INVALID_NONCE")


def _signature_verifies(signer: SignerKeyMaterial, signature: bytes, payload: bytes) -> bool:
    public_key = serialization.load_der_public_key(signer.spki_der)
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    try:
        public_key.verify(signature, payload, _PSS_SALT_32, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def _image_signature_entry(signer: SignerKeyMaterial, signature: bytes) -> _SignatureEntry:
    return {
        "key_id": signer.key_id,
        "signature": base64.b64encode(signature).decode("ascii"),
        "signature_algorithm": signer.algorithm,
    }


def _verified_image_signatures(
    signers: Sequence[SignerKeyMaterial], payload: bytes
) -> list[_SignatureEntry]:
    """Sign with every signer; list only signatures that verify (Google emulation, D-016/T-22)."""
    entries: list[_SignatureEntry] = []
    for signer in signers:
        signature = signer.sign(payload)
        if _signature_verifies(signer, signature, payload):
            entries.append(_image_signature_entry(signer, signature))
    return entries


def _parent(claims: dict[str, JsonValue], path: ClaimPath) -> dict[str, JsonValue]:
    if not path:
        raise ValueError("PATH_NOT_FOUND")
    node: JsonValue = claims
    for segment in path[:-1]:
        if not isinstance(node, dict) or segment not in node:
            raise ValueError("PATH_NOT_FOUND")
        node = node[segment]
    if not isinstance(node, dict):
        raise ValueError("PATH_NOT_FOUND")
    return node


def _apply_edit(claims: dict[str, JsonValue], edit: AlterClaim | DropClaim) -> None:
    parent = _parent(claims, edit.path)
    name = edit.path[-1]
    if isinstance(edit, AlterClaim):
        parent[name] = edit.value
    elif name in parent:
        del parent[name]
    else:
        raise ValueError("PATH_NOT_FOUND")


def _first_entry(signatures: list[_SignatureEntry]) -> _SignatureEntry:
    if not signatures:
        raise ValueError("PATH_NOT_FOUND")
    return signatures[0]


def _corrupted(sign: _Sign) -> _Sign:
    """Flip bit 0 (least significant) of the first signature byte (API.md §G #3)."""

    def sign_and_corrupt(signing_input: bytes) -> bytes:
        signature = bytearray(sign(signing_input))
        signature[0] ^= 0x01
        return bytes(signature)

    return sign_and_corrupt


def _empty_signature(signing_input: bytes) -> bytes:
    return b""


def frame_jws(header: bytes, payload: bytes, sign: Callable[[bytes], bytes]) -> str:
    signing_input = f"{_b64url(header)}.{_b64url(payload)}"
    return f"{signing_input}.{_b64url(sign(signing_input.encode('ascii')))}"


def _parse_claim_path(text: str) -> ClaimPath:
    if _CLAIM_PATH.fullmatch(text) is None:
        raise ValueError("INVALID_ALTERATION")
    return tuple(text.split("."))


def _reject_non_integer_number(text: str) -> JsonValue:
    raise ValueError(text)


def _parse_claim_value(text: str) -> JsonValue:
    """JSON if `text` parses to a JSON value without non-integer numbers, else the literal text."""
    try:
        value: JsonValue = json.loads(
            text,
            parse_float=_reject_non_integer_number,
            parse_constant=_reject_non_integer_number,
        )
    except (ValueError, RecursionError):
        return text
    return value


def parse_alteration(kind: Literal["alter", "drop", "case"], text: str) -> Alteration:
    if kind == "alter":
        path, separator, value = text.partition("=")
        if not separator:
            raise ValueError("INVALID_ALTERATION")
        claim_value = _parse_claim_value(value)
        try:
            _json_bytes(claim_value)
        except UnicodeEncodeError:
            raise ValueError("INVALID_ALTERATION") from None
        return AlterClaim(_parse_claim_path(path), claim_value)
    if kind == "drop":
        return DropClaim(_parse_claim_path(text))
    if kind == "case" and text in _CASE_IDS:
        return NamedCase(text)
    raise ValueError("INVALID_ALTERATION")


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
        # Signed once, like a registry signature: every token from this minter lists the same
        # verified entries, so a negative case differs from `valid` only where §G says.
        self._image_signatures = _verified_image_signatures(keys.signers, self._image_payload())

    def _claims_and_signatures(
        self, audience: str, nonces: Sequence[str], now: int
    ) -> tuple[dict[str, JsonValue], list[_SignatureEntry]]:
        _check_nonces(nonces)
        launch = self._launch
        signatures = [dict(entry) for entry in self._image_signatures]
        claims: dict[str, JsonValue] = {
            "iss": self._issuer,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + self._ttl_s,
            "hwmodel": SIM_HWMODEL,
            "swname": SWNAME,
            "secboot": True,
            "dbgstat": DBGSTAT_DISABLED,
            "submods": {
                "confidential_space": {"support_attributes": list(SUPPORT_ATTRIBUTES)},
                "container": {
                    "image_reference": launch.image_reference,
                    "image_digest": launch.image_digest,
                    "image_signatures": [*signatures],
                    "args": list(launch.args),
                    "env": dict(launch.env),
                },
            },
        }
        if len(nonces) == 1:
            claims["eat_nonce"] = nonces[0]
        elif nonces:
            claims["eat_nonce"] = list(nonces)
        return claims, signatures

    def _image_payload(self) -> bytes:
        return image_signature_payload(self._launch.image_reference, self._launch.image_digest)

    def _case_edits(
        self, case_id: str, now: int, signatures: list[_SignatureEntry]
    ) -> tuple[AlterClaim | DropClaim, ...]:
        """The claim edits of API.md §G for `case_id`, applied to the valid token's claims."""
        max_age = self._token_max_age_s
        launch = self._launch
        match case_id:
            case "alg_none" | "token_signature_corrupted":
                return ()
            case "issuer_wrong":
                return (AlterClaim(("iss",), "https://issuer.invalid"),)
            case "issuer_missing":
                return (DropClaim(("iss",)),)
            case "audience_wrong":
                return (AlterClaim(("aud",), "https://audience.invalid"),)
            case "audience_missing":
                return (DropClaim(("aud",)),)
            case "expired":
                return (AlterClaim(("iat",), now - 120), AlterClaim(("exp",), now - 60))
            case "exp_missing":
                return (DropClaim(("exp",)),)
            case "iat_stale":
                return (AlterClaim(("iat",), now - max_age - 60),)
            case "iat_future":
                return (AlterClaim(("iat",), now + max_age + 60),)
            case "nbf_future":
                return (AlterClaim(("nbf",), now + 600),)
            case "nonce_wrong":
                return (AlterClaim(("eat_nonce",), _WRONG_NONCE),)
            case "nonce_missing":
                return (DropClaim(("eat_nonce",)),)
            case "hwmodel_unlisted":
                return (AlterClaim(("hwmodel",), "GCP_AMD_SEV"),)
            case "swname_wrong":
                return (AlterClaim(("swname",), "GCE"),)
            case "secboot_false":
                return (AlterClaim(("secboot",), False),)
            case "dbgstat_enabled" | "debug_bad_signature":
                return (AlterClaim(("dbgstat",), "enabled"),)
            case "dbgstat_missing":
                return (DropClaim(("dbgstat",)),)
            case "stable_missing":
                path = ("submods", "confidential_space", "support_attributes")
                return (AlterClaim(path, ["LATEST", "USABLE"]),)
            case "digest_unknown":
                return (AlterClaim(("submods", "container", "image_digest"), _UNKNOWN_DIGEST),)
            case "signatures_insufficient":
                kept = signatures[: len(self._keys.signers) - 1]
                return (AlterClaim(_IMAGE_SIGNATURES, [*kept]),)
            case "signer_unknown":
                unknown = self._keys.unknown_signer
                entry = _image_signature_entry(unknown, unknown.sign(self._image_payload()))
                return (AlterClaim(_IMAGE_SIGNATURES, [*signatures[:-1], entry]),)
            case "signature_algorithm_mismatch":
                first = {
                    **_first_entry(signatures),
                    "signature_algorithm": _MISMATCHED_SIGNATURE_ALGORITHM,
                }
                return (AlterClaim(_IMAGE_SIGNATURES, [first, *signatures[1:]]),)
            case "args_altered":
                args: list[JsonValue] = [*launch.args, "--debug"]
                return (AlterClaim(("submods", "container", "args"), args),)
            case "env_altered":
                env: dict[str, JsonValue] = {**dict(launch.env), "TEECUSTODY_SIM_ALTERED": "1"}
                return (AlterClaim(("submods", "container", "env"), env),)
            case "key_id_duplicated":
                duplicate = dict(_first_entry(signatures))
                if len(signatures) < 2:
                    # Replacing the only entry with itself would mint a copy of `valid`.
                    raise ValueError("INVALID_ALTERATION")
                return (AlterClaim(_IMAGE_SIGNATURES, [*signatures[:-1], duplicate]),)
            case _:
                raise ValueError("UNKNOWN_CASE")

    def claims(self, audience: str, nonces: Sequence[str], now: int) -> dict[str, JsonValue]:
        return self._claims_and_signatures(audience, nonces, now)[0]

    def mint(
        self,
        audience: str,
        nonces: Sequence[str],
        now: int,
        alteration: Alteration | None = None,
    ) -> str:
        claims, signatures = self._claims_and_signatures(audience, nonces, now)
        header: JsonValue = {"alg": JWS_ALG, "kid": self._keys.issuer_kid, "typ": "JWT"}
        sign: _Sign = self._keys.sign_jws
        if isinstance(alteration, AlterClaim | DropClaim):
            _apply_edit(claims, alteration)
        elif isinstance(alteration, NamedCase):
            for edit in self._case_edits(alteration.case_id, now, signatures):
                _apply_edit(claims, edit)
            if alteration.case_id == "alg_none":
                header = {"alg": "none", "typ": "JWT"}
                sign = _empty_signature
            elif alteration.case_id in _CORRUPTED_SIGNATURE_CASES:
                sign = _corrupted(sign)
        return frame_jws(_json_bytes(header), _json_bytes(claims), sign)
