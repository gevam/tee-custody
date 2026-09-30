"""Workload identity key (IK)."""


class IdentityKey:
    @classmethod
    def generate(cls) -> "IdentityKey":
        raise NotImplementedError("T-06")

    def public_bytes(self) -> bytes:
        raise NotImplementedError("T-06")
