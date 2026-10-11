"""The workload's own image digest, read from its launcher-supplied token (spec §5.1 step 3)."""

import re
from typing import Final

from teecustody.attest.ports import AttestationToken

IMAGE_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}")  # fullmatch only (R-7)


def own_image_digest(token: AttestationToken, *, max_token_bytes: int) -> str:
    raise NotImplementedError("T-13")
