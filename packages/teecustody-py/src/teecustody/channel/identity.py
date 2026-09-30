"""Workload identity key (IK)."""


class IdentityKey:
    @classmethod
    def generate(cls) -> "IdentityKey":
        raise NotImplementedError

    def public_bytes(self) -> bytes:
        raise NotImplementedError
