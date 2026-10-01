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
    try:
        size = len(token.encode("utf-8"))
    except UnicodeEncodeError:
        raise _rejected() from None
    if size > max_token_bytes:
        raise _rejected()
    segments = token.split(".")
    if len(segments) != 3:
        raise _rejected()
    claims = _decode_payload(segments[1])
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


def _decode_payload(segment: str) -> dict[str, object]:
    if _BASE64URL.fullmatch(segment) is None:
        raise _rejected()
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except binascii.Error:
        raise _rejected() from None
    if _b64url(raw) != segment:
        raise _rejected()
    try:
        claims = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise _rejected() from None
    if not isinstance(claims, dict):
        raise _rejected()
    return claims


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _rejected() -> LauncherError:
    return LauncherError(LauncherErrorCode.TOKEN_REJECTED)
