"""Local, untrusted parsing of attestation token metadata."""

from teecustody.attest.ports import AttestationToken


def parse_token_metadata(
    token: str, *, audience: str, expected_nonce: str, max_token_bytes: int
) -> AttestationToken:
    raise NotImplementedError("T-06")
