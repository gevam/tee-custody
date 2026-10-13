"""Canonical pre-key bundle builder (INC-2-API §4.7; spec §5.1). Body belongs to T-22."""

from collections.abc import Sequence

from teecustody.attest.ports import AttestationToken
from teecustody.channel.prekeys import PreKeyPublic


def build_bundle(
    *,
    instance_id: str,
    token: AttestationToken,
    ik_pub: bytes,
    prekeys: Sequence[PreKeyPublic],
    published_at: int,
) -> bytes:
    raise NotImplementedError("T-22")
