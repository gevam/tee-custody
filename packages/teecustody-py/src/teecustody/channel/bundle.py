"""Canonical pre-key bundle builder (INC-2-API §4.7; spec §5.1). Signs nothing (SR-14)."""

from collections.abc import Sequence

from teecustody.attest.ports import AttestationToken
from teecustody.channel.codec import PreKeyBundle, PreKeyEntry, encode_bundle
from teecustody.channel.prekeys import PreKeyPublic


def build_bundle(
    *,
    instance_id: str,
    token: AttestationToken,
    ik_pub: bytes,
    prekeys: Sequence[PreKeyPublic],
    published_at: int,
) -> bytes:
    """Canonical `prekey-bundle`; the codec refuses 0 or > 256 entries and non-ascending ids."""
    return encode_bundle(
        PreKeyBundle(
            instance_id=instance_id,
            token=token.value,
            ik_pub=ik_pub,
            published_at=published_at,
            prekeys=tuple(
                PreKeyEntry(id=p.id, pub=p.pub, not_after=p.not_after, sig=p.sig) for p in prekeys
            ),
        )
    )
