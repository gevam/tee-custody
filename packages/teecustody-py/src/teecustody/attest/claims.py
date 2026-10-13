"""The workload's own image digest, read from its launcher-supplied token (spec §5.1 step 3)."""

import base64
import json
import re
from typing import Final

from teecustody.attest.ports import AttestationToken, LauncherError, LauncherErrorCode

IMAGE_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}")  # fullmatch only (R-7)


def own_image_digest(token: AttestationToken, *, max_token_bytes: int) -> str:
    if len(token.value.encode("ascii")) > max_token_bytes:
        raise LauncherError(LauncherErrorCode.TOKEN_REJECTED) from None
    payload = token.value.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    digest: str = claims["submods"]["container"]["image_digest"]
    return digest
