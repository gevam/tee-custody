"""Identity and launcher nonce derivation (API.md §A)."""


def identity_nonce(identity_public_key: bytes) -> bytes:
    raise NotImplementedError("T-06")


def launcher_nonce(identity_nonce: bytes) -> str:
    raise NotImplementedError("T-06")
