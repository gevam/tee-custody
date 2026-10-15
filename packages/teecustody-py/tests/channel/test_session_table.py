"""T-23 criteria 9-12: the bounded session table (R-8, D2-19, NFR-3; INC-2-API §4.9)."""

import os
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.codec import FrameAad, OpenResultAad, encode_frame_aad
from teecustody.channel.ports import CloseReason, SessionInfo
from teecustody.channel.session import (
    Session,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
    _nonce,
)
from teecustody.secrets import Secret

INSTANCE_ID = "fedcba9876543210" * 2
CLIENT_A = "a1" * 16
CLIENT_B = "b2" * 16
CLIENT_C = "c3" * 16
CLIENT_D = "d4" * 16
SID_1 = b"\x01" * 16
SID_2 = b"\x02" * 16
SID_3 = b"\x03" * 16
SID_9 = b"\x09" * 16
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


# ---------------------------------------------------------------- criterion 10 (R-8)
def _frame(
    keys: Keys, session_id: bytes, seq: int, *, forged: bool = False
) -> tuple[FrameAad, bytes, bytes]:
    aad = FrameAad(session_id=session_id, seq=seq, op="test.echo")
    aad_bytes = encode_frame_aad(aad)
    key = os.urandom(32) if forged else keys.sk_c2t.reveal()
    return aad, aad_bytes, AESGCM(key).encrypt(_nonce(seq), b"p", aad_bytes)


def test_a_full_table_evicts_exactly_the_idle_session() -> None:
    world = World(max_sessions=2)
    _s1, k1 = world.create(SID_1, CLIENT_A)
    s2, k2 = world.create(SID_2, CLIENT_B)
    world.clock.now += 90
    s2.open_c2t(*_frame(k2, SID_2, 0), world.clock())
    world.clock.now += 10
    s3, k3 = world.create(SID_3, CLIENT_C)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.EVICTED)]
    assert k1.wiped
    assert world.table.get(SID_1) is None
    assert world.table.get(SID_2) is s2
    assert world.table.get(SID_3) is s3
    assert k2.live
    assert k3.live


def test_a_full_table_of_active_sessions_refuses_and_evicts_nobody() -> None:
    world = World(max_sessions=2)
    s1, k1 = world.create(SID_1, CLIENT_A)
    s2, k2 = world.create(SID_2, CLIENT_B)
    world.clock.now += 59.999
    with pytest.raises(OverflowError, match=r"^SESSIONS_FULL$"):
        world.create(SID_3, CLIENT_C)
    assert world.closes == []
    assert world.table.get(SID_1) is s1
    assert world.table.get(SID_2) is s2
    assert k1.live
    assert k2.live


def test_a_session_idle_exactly_the_minimum_is_evictable() -> None:
    world = World(max_sessions=1)
    _s1, k1 = world.create(SID_1, CLIENT_A)
    world.clock.now += 60
    world.create(SID_2, CLIENT_B)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.EVICTED)]
    assert k1.wiped


def test_equal_activity_evicts_the_smallest_session_id() -> None:
    world = World(max_sessions=3)
    world.create(SID_9, CLIENT_A)
    world.create(SID_1, CLIENT_B)
    world.create(SID_2, CLIENT_C)
    world.clock.now += 61
    world.create(SID_3, CLIENT_D)
    assert world.closes == [(_info(SID_1, CLIENT_B), CloseReason.EVICTED)]


def test_the_least_recently_active_session_is_chosen_not_the_oldest() -> None:
    world = World(max_sessions=2)
    s1, k1 = world.create(SID_1, CLIENT_A)
    world.clock.now += 10
    world.create(SID_2, CLIENT_B)
    world.clock.now += 10
    s1.open_c2t(*_frame(k1, SID_1, 0), world.clock())
    world.clock.now += 100
    world.create(SID_3, CLIENT_C)
    assert world.closes == [(_info(SID_2, CLIENT_B), CloseReason.EVICTED)]


def test_at_most_one_session_is_evicted_per_create() -> None:
    world = World(max_sessions=3)
    world.create(SID_1, CLIENT_A)
    world.create(SID_2, CLIENT_B)
    world.create(SID_9, CLIENT_C)
    world.clock.now += 300
    world.create(SID_3, CLIENT_D)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.EVICTED)]
    assert world.table.get(SID_2) is not None
    assert world.table.get(SID_9) is not None


@pytest.mark.parametrize("rejection", ["forged", "replayed", "foreign"])
def test_a_rejected_or_unauthenticated_frame_never_refreshes_activity(rejection: str) -> None:
    world = World(max_sessions=2)
    s1, k1 = world.create(SID_1, CLIENT_A)
    world.clock.now += 5
    world.create(SID_2, CLIENT_B)
    s1.open_c2t(*_frame(k1, SID_1, 0), world.clock())
    world.clock.now += 50
    frame = {
        "forged": _frame(k1, SID_1, 1, forged=True),
        "replayed": _frame(k1, SID_1, 0),
        "foreign": _frame(k1, SID_2, 1),
    }[rejection]
    with pytest.raises(SessionReject) as err:
        s1.open_c2t(*frame, world.clock())
    assert err.value.code in {SessionRejectCode.AUTH_FAILED, SessionRejectCode.SEQ_REJECTED}
    world.clock.now += 20
    world.create(SID_3, CLIENT_C)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.EVICTED)]


def test_sessions_past_the_idle_timeout_expire_before_any_eviction() -> None:
    world = World(max_sessions=2)
    _s1, k1 = world.create(SID_1, CLIENT_A)
    world.clock.now += 850
    s2, k2 = world.create(SID_2, CLIENT_B)
    world.clock.now += 50
    world.create(SID_3, CLIENT_C)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.IDLE_TIMEOUT)]
    assert k1.wiped
    assert world.table.get(SID_2) is s2
    assert k2.live


# ---------------------------------------------------------------- criterion 11
def test_a_used_sealer_is_refused_and_the_caller_keeps_it() -> None:
    world = World()
    existing, existing_keys = world.create(SID_1, CLIENT_A)
    sk_c2t, sk_t2c = Secret(os.urandom(32)), Secret(os.urandom(32))
    sealer = T2cSealer(sk_t2c)
    sealer.seal_open_result(OpenResultAad(session_id=None, request_id=bytes(16)), b"no")
    with pytest.raises(ValueError, match=r"^T2C_USED$"):
        world.table.create(session_id=SID_2, client_id=CLIENT_A, sk_c2t=sk_c2t, t2c=sealer)
    assert world.table.get(SID_2) is None
    assert world.table.get(SID_1) is existing
    assert world.closes == []
    assert existing_keys.live
    assert not sk_c2t.wiped
    assert not sk_t2c.wiped
    aad_bytes, ct = sealer.seal_frame_result("test.echo", SID_2, b"still mine")
    assert AESGCM(sk_t2c.reveal()).decrypt(_nonce(1), ct, aad_bytes) == b"still mine"


def test_a_full_table_leaves_the_fresh_sealer_with_the_caller_for_the_rejection() -> None:
    world = World(max_sessions=1)
    world.create(SID_1, CLIENT_A)
    sk_c2t, sk_t2c = Secret(os.urandom(32)), Secret(os.urandom(32))
    sealer = T2cSealer(sk_t2c)
    with pytest.raises(OverflowError, match=r"^SESSIONS_FULL$"):
        world.table.create(session_id=SID_2, client_id=CLIENT_B, sk_c2t=sk_c2t, t2c=sealer)
    assert not sk_c2t.wiped
    aad = OpenResultAad(session_id=None, request_id=bytes(16))
    aad_bytes, ct = sealer.seal_open_result(aad, b"full")
    assert AESGCM(sk_t2c.reveal()).decrypt(_nonce(0), ct, aad_bytes) == b"full"


# ---------------------------------------------------------------- criterion 12
def test_expire_idle_closes_sessions_idle_for_the_timeout_and_wipes_them() -> None:
    world = World()
    _s1, k1 = world.create(SID_1, CLIENT_A)
    world.clock.now += 100
    s2, k2 = world.create(SID_2, CLIENT_B)
    world.clock.now += 799.5
    assert world.table.expire_idle() == 0
    world.clock.now += 0.5
    assert world.table.expire_idle() == 1
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.IDLE_TIMEOUT)]
    assert k1.wiped
    assert world.table.get(SID_2) is s2
    assert k2.live


def test_close_all_shuts_every_session_down_and_wipes_every_key() -> None:
    world = World()
    _s1, k1 = world.create(SID_1, CLIENT_A)
    _s2, k2 = world.create(SID_2, CLIENT_B)
    world.table.close_all()
    assert sorted(world.closes, key=lambda close: close[0].session_id) == [
        (_info(SID_1, CLIENT_A), CloseReason.SHUTDOWN),
        (_info(SID_2, CLIENT_B), CloseReason.SHUTDOWN),
    ]
    assert k1.wiped
    assert k2.wiped
    assert world.table.get(SID_1) is None
    assert world.table.get(SID_2) is None


# ---------------------------------------------------------------- edges: close, on_close, limits
def test_close_is_idempotent_and_reports_once() -> None:
    world = World()
    _s1, k1 = world.create(SID_1, CLIENT_A)
    world.table.close(SID_1, CloseReason.CLIENT_CLOSE)
    world.table.close(SID_1, CloseReason.CLIENT_CLOSE)
    world.table.close(SID_9, CloseReason.CLIENT_CLOSE)
    assert world.closes == [(_info(SID_1, CLIENT_A), CloseReason.CLIENT_CLOSE)]
    assert k1.wiped


def test_an_on_close_failure_is_swallowed_after_the_keys_are_wiped() -> None:
    clock = FakeClock()
    seen: list[CloseReason] = []

    def failing(info: SessionInfo, reason: CloseReason) -> None:
        seen.append(reason)
        raise RuntimeError("host hook failed")

    table = SessionTable(
        instance_id=INSTANCE_ID,
        max_sessions=1,
        idle_timeout_s=900,
        evict_min_idle_s=60,
        on_close=failing,
        clock=clock,
    )
    sk_c2t, sk_t2c = Secret(os.urandom(32)), Secret(os.urandom(32))
    table.create(session_id=SID_1, client_id=CLIENT_A, sk_c2t=sk_c2t, t2c=T2cSealer(sk_t2c))
    clock.now += 60
    second = table.create(
        session_id=SID_2,
        client_id=CLIENT_B,
        sk_c2t=Secret(os.urandom(32)),
        t2c=T2cSealer(Secret(os.urandom(32))),
    )
    assert seen == [CloseReason.EVICTED]
    assert sk_c2t.wiped
    assert sk_t2c.wiped
    assert table.get(SID_1) is None
    assert table.get(SID_2) is second
    table.close(SID_2, CloseReason.CLIENT_CLOSE)
    assert seen == [CloseReason.EVICTED, CloseReason.CLIENT_CLOSE]


@pytest.mark.parametrize(
    ("max_sessions", "idle_timeout_s", "evict_min_idle_s"),
    [(0, 900, 60), (4, 0, 0), (4, 900, 0), (4, 59, 60), (-1, 900, 60)],
)
def test_the_table_refuses_invalid_limits(
    max_sessions: int, idle_timeout_s: int, evict_min_idle_s: int
) -> None:
    with pytest.raises(ValueError, match=r"^SESSION_LIMITS$"):
        SessionTable(
            instance_id=INSTANCE_ID,
            max_sessions=max_sessions,
            idle_timeout_s=idle_timeout_s,
            evict_min_idle_s=evict_min_idle_s,
            on_close=lambda info, reason: None,
            clock=FakeClock(),
        )


def test_the_smallest_valid_limits_are_accepted() -> None:
    table = SessionTable(
        instance_id=INSTANCE_ID,
        max_sessions=1,
        idle_timeout_s=1,
        evict_min_idle_s=1,
        on_close=lambda info, reason: None,
        clock=FakeClock(),
    )
    assert table.get(SID_1) is None


def test_a_session_id_already_in_use_is_refused_without_side_effects() -> None:
    world = World()
    existing, existing_keys = world.create(SID_1, CLIENT_A)
    sk_c2t, sealer = Secret(os.urandom(32)), T2cSealer(Secret(os.urandom(32)))
    with pytest.raises(ValueError, match=r"^SESSION_ID_IN_USE$"):
        world.table.create(session_id=SID_1, client_id=CLIENT_B, sk_c2t=sk_c2t, t2c=sealer)
    assert world.table.get(SID_1) is existing
    assert existing_keys.live
    assert world.closes == []
    assert not sk_c2t.wiped
