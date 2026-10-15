"""Pre-key store (INC-2-API §4.7; spec §4, §5.1; SR-14, NFR-3).

The only caller of `IdentityKey.sign`: each pre-key is signed once, at generation, over the
156-byte layout of `prekey_signing_message`. Private keys are single-use `Secret`s, wiped on
expiry, on shutdown and when their generation fails.
"""

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from teecustody.attest.claims import IMAGE_DIGEST_PATTERN
from teecustody.channel import hpke
from teecustody.channel.codec import INSTANCE_ID_PATTERN, prekey_signing_message
from teecustody.channel.identity import IdentityKey
from teecustody.config import ChannelParams
from teecustody.secrets import Secret

_MAX_PREKEY_ID: Final = 2**32 - 1  # uint32 (INC-2-API §2)
_CONSUMED_WINDOW_S: Final = 2 * 3600  # history kept for `consumed_since` (PREKEY_BURN_HIGH)


@dataclass(frozen=True, slots=True)
class PreKeyPublic:
    id: int
    pub: bytes
    not_after: int
    sig: bytes


class PreKeyStore:
    """Bounded pool of single-use X25519 pre-keys; "live" = not taken and `not_after > now`."""

    def __init__(
        self,
        *,
        instance_id: str,
        identity: IdentityKey,
        image_digest: str,
        params: ChannelParams,
        clock: Callable[[], float],
    ) -> None:
        if not INSTANCE_ID_PATTERN.fullmatch(instance_id):
            raise ValueError("INSTANCE_ID_RANGE")
        if not IMAGE_DIGEST_PATTERN.fullmatch(image_digest):
            raise ValueError("IMAGE_DIGEST_RANGE")
        self._instance_id = instance_id
        self._identity = identity
        self._image_digest = image_digest
        self._params = params
        self._clock = clock
        self._keys: dict[int, tuple[PreKeyPublic, Secret]] = {}
        self._next_id = 0
        self._taken_at: deque[float] = deque()

    def top_up(self) -> int:
        live = len(self.public_entries())
        if live and live >= self._params.prekey_low_water:
            return 0
        count = self._params.prekey_batch - live
        for _ in range(count):
            self._generate()
        return count

    def _generate(self) -> None:
        prekey_id = self._next_id
        if prekey_id > _MAX_PREKEY_ID:
            raise RuntimeError("PREKEY_IDS_EXHAUSTED")  # ids are never reused: restart
        self._next_id += 1
        private, pub = hpke.generate_keypair()
        not_after = math.floor(self._clock()) + self._params.prekey_ttl_s
        try:
            message = prekey_signing_message(
                self._instance_id, prekey_id, pub, not_after, self._image_digest
            )
            sig = self._identity.sign(message)
        except BaseException:
            private.wipe()
            raise
        self._keys[prekey_id] = (PreKeyPublic(prekey_id, pub, not_after, sig), private)

    def expire(self) -> int:
        now = self._clock()
        return self._destroy(
            [i for i, (public, _) in self._keys.items() if public.not_after <= now]
        )

    def public_entries(self) -> tuple[PreKeyPublic, ...]:
        now = self._clock()
        return tuple(public for public, _ in self._keys.values() if public.not_after > now)

    def take(self, prekey_id: int) -> Secret:
        slot = self._keys.pop(prekey_id, None) if type(prekey_id) is int else None
        if slot is None:
            raise KeyError("PREKEY_UNKNOWN")
        public, private = slot
        now = self._clock()
        if public.not_after <= now:
            private.wipe()
            raise KeyError("PREKEY_UNKNOWN")
        self._taken_at.append(now)
        while self._taken_at[0] < now - _CONSUMED_WINDOW_S:
            self._taken_at.popleft()
        return private

    def consumed_since(self, since: float) -> int:
        return sum(1 for at in self._taken_at if at >= since)

    def destroy_all(self) -> None:
        self._destroy(list(self._keys))

    def _destroy(self, prekey_ids: list[int]) -> int:
        for prekey_id in prekey_ids:
            _, private = self._keys.pop(prekey_id)
            private.wipe()
        return len(prekey_ids)
