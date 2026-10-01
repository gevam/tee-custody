"""Negative-case catalog (API.md §G rows 2..37, in table order; spec §13.2, §15.3; SR-12)."""

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class NegativeCase:
    case_id: str
    check: str
    error_code: str
    altered: tuple[str, ...]
    debug_event: bool


_IMAGE_SIGNATURES: Final = "submods.container.image_signatures"

NEGATIVE_CASES: Final[tuple[NegativeCase, ...]] = (
    NegativeCase("alg_none", "signature", "UNSUPPORTED_ALGORITHM", (), False),
    NegativeCase("token_signature_corrupted", "signature", "UNTRUSTED_SIGNER", (), False),
    NegativeCase("issuer_wrong", "issuer", "CLAIM_MISMATCH", ("iss",), False),
    NegativeCase("issuer_missing", "issuer", "CLAIM_MISSING", ("iss",), False),
    NegativeCase("audience_wrong", "audience", "CLAIM_MISMATCH", ("aud",), False),
    NegativeCase("audience_missing", "audience", "CLAIM_MISSING", ("aud",), False),
    NegativeCase("expired", "time", "EXPIRED", ("exp", "iat"), False),
    NegativeCase("exp_missing", "time", "CLAIM_MISSING", ("exp",), False),
    NegativeCase("iat_stale", "time", "EXPIRED", ("iat",), False),
    NegativeCase("iat_future", "time", "NOT_YET_VALID", ("iat",), False),
    NegativeCase("nbf_future", "time", "NOT_YET_VALID", ("nbf",), False),
    NegativeCase("nonce_wrong", "nonce", "CLAIM_MISMATCH", ("eat_nonce",), False),
    NegativeCase("nonce_missing", "nonce", "CLAIM_MISSING", ("eat_nonce",), False),
    NegativeCase("hwmodel_unlisted", "platform", "CLAIM_MISMATCH", ("hwmodel",), False),
    NegativeCase("swname_wrong", "platform", "CLAIM_MISMATCH", ("swname",), False),
    NegativeCase("secboot_false", "platform", "CLAIM_MISMATCH", ("secboot",), False),
    NegativeCase("dbgstat_enabled", "platform", "CLAIM_MISMATCH", ("dbgstat",), True),
    NegativeCase("dbgstat_missing", "platform", "CLAIM_MISSING", ("dbgstat",), False),
    NegativeCase(
        "stable_missing",
        "support_attributes",
        "CLAIM_MISMATCH",
        ("submods.confidential_space.support_attributes",),
        False,
    ),
    NegativeCase(
        "digest_unknown", "image", "CLAIM_MISMATCH", ("submods.container.image_digest",), False
    ),
    NegativeCase(
        "signatures_insufficient", "image", "UNTRUSTED_SIGNER", (_IMAGE_SIGNATURES,), False
    ),
    NegativeCase("signer_unknown", "image", "UNTRUSTED_SIGNER", (_IMAGE_SIGNATURES,), False),
    NegativeCase(
        "signature_algorithm_mismatch", "image", "UNTRUSTED_SIGNER", (_IMAGE_SIGNATURES,), False
    ),
    NegativeCase(
        "args_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.args",), False
    ),
    NegativeCase(
        "env_altered", "launch_config", "CLAIM_MISMATCH", ("submods.container.env",), False
    ),
    NegativeCase("debug_bad_signature", "signature", "UNTRUSTED_SIGNER", ("dbgstat",), False),
    NegativeCase("key_id_duplicated", "image", "UNTRUSTED_SIGNER", (_IMAGE_SIGNATURES,), False),
    NegativeCase("hwmodel_missing", "platform", "CLAIM_MISSING", ("hwmodel",), False),
    NegativeCase("swname_missing", "platform", "CLAIM_MISSING", ("swname",), False),
    NegativeCase("secboot_missing", "platform", "CLAIM_MISSING", ("secboot",), False),
    NegativeCase(
        "support_attributes_missing",
        "support_attributes",
        "CLAIM_MISSING",
        ("submods.confidential_space.support_attributes",),
        False,
    ),
    NegativeCase(
        "digest_missing", "image", "CLAIM_MISSING", ("submods.container.image_digest",), False
    ),
    NegativeCase("signatures_missing", "image", "CLAIM_MISSING", (_IMAGE_SIGNATURES,), False),
    NegativeCase(
        "args_missing", "launch_config", "CLAIM_MISSING", ("submods.container.args",), False
    ),
    NegativeCase(
        "env_missing", "launch_config", "CLAIM_MISSING", ("submods.container.env",), False
    ),
    NegativeCase("kid_unknown", "signature", "UNTRUSTED_SIGNER", (), False),
)
