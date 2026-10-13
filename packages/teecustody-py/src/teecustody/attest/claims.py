"""The workload's own image digest, read from its launcher-supplied token (spec §5.1 step 3).

The token comes from the local launcher, a trusted source (spec §11), so its signature is not
verified here; its shape is, strictly, because the digest is bound into every pre-key signature.
"""

import base64
import binascii
import json
import re
from typing import Final

from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode

IMAGE_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}")  # fullmatch only (R-7)

_BASE64URL: Final = re.compile(r"[A-Za-z0-9_-]+")


def own_image_digest(token: AttestationToken, *, max_token_bytes: int) -> str:
    digest = _read_digest(token.value, max_token_bytes)
    if digest is None:
        raise LauncherError(LauncherErrorCode.TOKEN_REJECTED) from None
    return digest


# The helpers below return None instead of raising, so the rejection is never chained to an
# exception that holds token bytes.


def _read_digest(value: str, max_token_bytes: int) -> str | None:
    size = _ascii_size(value)
    if size is None or size > max_token_bytes:
        return None
    segments = value.split(".")
    if len(segments) != 3:
        return None
    header, payload, signature = (_b64url_decode(segment) for segment in segments)
    if header is None or payload is None or signature is None:
        return None
    container = _object_at(_json_loads(payload), "submods", "container")
    digest = container.get("image_digest") if container is not None else None
    if not isinstance(digest, str) or IMAGE_DIGEST_PATTERN.fullmatch(digest) is None:
        return None
    return digest


def _ascii_size(value: str) -> int | None:
    try:
        return len(value.encode("ascii"))
    except UnicodeEncodeError:
        return None


def _b64url_decode(segment: str) -> bytes | None:
    """Strict, canonical, unpadded, non-empty base64url; otherwise None."""
    if _BASE64URL.fullmatch(segment) is None:
        return None
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except binascii.Error:
        return None
    canonical = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return raw if canonical == segment else None


def _json_loads(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


def _object_at(value: object, *path: str) -> dict[str, object] | None:
    """The JSON object reached through `path`, if every step is an object; otherwise None."""
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value if isinstance(value, dict) else None
