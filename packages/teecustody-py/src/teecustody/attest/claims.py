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

# SR-3 configured limit: the deepest JSON nesting the payload may have, counting the top-level
# object as 1 (matches DecodeLimits.max_depth). Checked on the text before json.loads runs.
_MAX_JSON_DEPTH: Final = 16


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
        text = raw.decode("utf-8")
        return json.loads(text) if _within_depth(text) else None
    except ValueError:
        return None


def _within_depth(text: str) -> bool:
    """True if no `[`/`{` outside a JSON string opens a level deeper than _MAX_JSON_DEPTH."""
    depth = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _object_at(value: object, *path: str) -> dict[str, object] | None:
    """The JSON object reached through `path`, if every step is an object; otherwise None."""
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value if isinstance(value, dict) else None
