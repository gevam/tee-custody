"""Local, untrusted parsing of attestation token metadata.

The signature is not verified here: the parsed claims only schedule refresh and catch a launcher
that answered for the wrong audience or nonce. Clients verify the token independently (spec §6).
"""

import base64
import binascii
import json
import re
from typing import TypeGuard

from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode

_BASE64URL = re.compile(r"[A-Za-z0-9_-]+")


def parse_token_metadata(
    token: str, *, audience: str, expected_nonce: str, max_token_bytes: int
) -> AttestationToken:
    size = _utf8_size(token)
    if size is None or size > max_token_bytes:
        raise _rejected()
    segments = token.split(".")
    if len(segments) != 3:
        raise _rejected()
    claims = _decode_payload(segments[1])
    if claims is None:
        raise _rejected()
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if not (_is_int(issued_at) and _is_int(expires_at) and expires_at > issued_at):
        raise _rejected()
    if claims.get("aud") != audience:
        raise _rejected()
    nonce = claims.get("eat_nonce")
    if nonce != expected_nonce and nonce != [expected_nonce]:
        raise _rejected()
    return AttestationToken(value=token, issued_at=issued_at, expires_at=expires_at)


# The helpers below return None instead of raising, so a rejection is never chained to an
# exception that holds token bytes.


def _utf8_size(text: str) -> int | None:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _decode_payload(segment: str) -> dict[str, object] | None:
    """Strict, canonical, unpadded base64url of a UTF-8 JSON object; otherwise None."""
    if _BASE64URL.fullmatch(segment) is None:
        return None
    raw = _b64url_decode(segment)
    if raw is None or _b64url(raw) != segment:
        return None
    claims = _json_loads(raw)
    return claims if isinstance(claims, dict) else None


def _b64url_decode(segment: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except binascii.Error:
        return None


def _json_loads(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _rejected() -> LauncherError:
    return LauncherError(LauncherErrorCode.TOKEN_REJECTED)
