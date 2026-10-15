"""T-23 criteria 9-12: the bounded session table (R-8, D2-19, NFR-3; INC-2-API §4.9)."""

import os
from dataclasses import dataclass

from teecustody.channel.ports import CloseReason, SessionInfo
from teecustody.channel.session import Session, SessionTable, T2cSealer
from teecustody.secrets import Secret

INSTANCE_ID = "fedcba9876543210" * 2
CLIENT_A = "a1" * 16
CLIENT_B = "b2" * 16
SID_1 = b"\x01" * 16
SID_2 = b"\x02" * 16
SID_3 = b"\x03" * 16
T0 = 1_900_000_000.0


class FakeClock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now


@dataclass
class Keys:
    sk_c2t: Secret
    sk_t2c: Secret

    @property
    def wiped(self) -> bool:
        return self.sk_c2t.wiped and self.sk_t2c.wiped

    @property
    def live(self) -> bool:
        return not self.sk_c2t.wiped and not self.sk_t2c.wiped


class World:
    def __init__(self, *, max_sessions: int = 4) -> None:
        self.clock = FakeClock()
        self.closes: list[tuple[SessionInfo, CloseReason]] = []
        self.table = SessionTable(
            instance_id=INSTANCE_ID,
            max_sessions=max_sessions,
            idle_timeout_s=900,
            evict_min_idle_s=60,
            on_close=lambda info, reason: self.closes.append((info, reason)),
            clock=self.clock,
        )

    def create(self, session_id: bytes, client_id: str) -> tuple[Session, Keys]:
        keys = Keys(Secret(os.urandom(32)), Secret(os.urandom(32)))
        session = self.table.create(
            session_id=session_id,
            client_id=client_id,
            sk_c2t=keys.sk_c2t,
            t2c=T2cSealer(keys.sk_t2c),
        )
        return session, keys


def _info(session_id: bytes, client_id: str) -> SessionInfo:
    return SessionInfo(client_id=client_id, session_id=session_id, instance_id=INSTANCE_ID)


# ---------------------------------------------------------------- criterion 9
def test_a_new_session_for_a_live_principal_replaces_the_old_one() -> None:
    world = World()
    _old, old_keys = world.create(SID_1, CLIENT_A)
    other, other_keys = world.create(SID_2, CLIENT_B)
    new, new_keys = world.create(SID_3, CLIENT_A)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.REPLACED)]
    assert old_keys.wiped
    assert world.table.get(SID_1) is None
    assert world.table.get(SID_3) is new
    assert new_keys.live
    assert world.table.get(SID_2) is other
    assert other_keys.live
