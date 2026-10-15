"""Pre-key store (INC-2-API §4.7; spec §4, §5.1). `PreKeyPublic` is frozen; bodies: T-22."""

import math
from collections.abc import Callable
from dataclasses import dataclass

from teecustody.channel import hpke
from teecustody.channel.codec import prekey_signing_message
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
        self._instance_id = instance_id
        self._identity = identity
        self._image_digest = image_digest
        self._params = params
        self._clock = clock
        self._keys: dict[int, tuple[PreKeyPublic, Secret]] = {}
        self._next_id = 0

    def top_up(self) -> int:
        live = len(self._keys)
        if live >= self._params.prekey_low_water:
            return 0
        count = self._params.prekey_batch - live
        for _ in range(count):
            self._generate()
        return count

    def _generate(self) -> None:
        prekey_id = self._next_id
        self._next_id += 1
        private, pub = hpke.generate_keypair()
        not_after = math.floor(self._clock()) + self._params.prekey_ttl_s
        sig = self._identity.sign(
            prekey_signing_message(self._instance_id, prekey_id, pub, not_after, self._image_digest)
        )
        self._keys[prekey_id] = (PreKeyPublic(prekey_id, pub, not_after, sig), private)

    def expire(self) -> int:
        raise NotImplementedError("T-22")

    def public_entries(self) -> tuple[PreKeyPublic, ...]:
        return tuple(public for public, _ in self._keys.values())

    def take(self, prekey_id: int) -> Secret:
        slot = self._keys.pop(prekey_id, None)
        if slot is None:
            raise KeyError("PREKEY_UNKNOWN")
        public, private = slot
        if public.not_after <= self._clock():
            private.wipe()
            raise KeyError("PREKEY_UNKNOWN")
        return private

    def consumed_since(self, since: float) -> int:
        raise NotImplementedError("T-22")

    def destroy_all(self) -> None:
        raise NotImplementedError("T-22")
