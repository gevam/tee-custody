"""Pre-key store (INC-2-API §4.7; spec §4, §5.1). `PreKeyPublic` is frozen; bodies: T-22."""

from collections.abc import Callable
from dataclasses import dataclass

from teecustody.channel.identity import IdentityKey
from teecustody.config import ChannelParams
from teecustody.secrets import Secret


@dataclass(frozen=True, slots=True)
class PreKeyPublic:
    id: int
    pub: bytes
    not_after: int
    sig: bytes


class PreKeyStore:
    def __init__(
        self,
        *,
        instance_id: str,
        identity: IdentityKey,
        image_digest: str,
        params: ChannelParams,
        clock: Callable[[], float],
    ) -> None:
        raise NotImplementedError("T-22")

    def top_up(self) -> int:
        raise NotImplementedError("T-22")

    def expire(self) -> int:
        raise NotImplementedError("T-22")

    def public_entries(self) -> tuple[PreKeyPublic, ...]:
        raise NotImplementedError("T-22")

    def take(self, prekey_id: int) -> Secret:
        raise NotImplementedError("T-22")

    def consumed_since(self, since: float) -> int:
        raise NotImplementedError("T-22")

    def destroy_all(self) -> None:
        raise NotImplementedError("T-22")
