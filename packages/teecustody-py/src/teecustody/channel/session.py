"""Session keys, the t2c sealer and the session table (INC-2-API §4.9; API-TL §2; D2-16, R-5, R-8).

`SessionRejectCode` and `SessionReject` are frozen; bodies belong to T-23.
"""

from collections.abc import Callable
from enum import StrEnum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from teecustody.channel.codec import (
    MAX_SEQ,
    FrameAad,
    OpenResultAad,
    encode_frame_aad,
    encode_open_result_aad,
)
from teecustody.channel.ports import CloseReason, SessionInfo
from teecustody.secrets import Secret


class SessionRejectCode(StrEnum):
    SEQ_REJECTED = "SEQ_REJECTED"
    AUTH_FAILED = "AUTH_FAILED"
    EXHAUSTED = "EXHAUSTED"
    USED = "USED"


class SessionReject(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: SessionRejectCode

    def __init__(self, code: SessionRejectCode) -> None:
        super().__init__(code.value)
        self.code = code


def _nonce(seq: int) -> bytes:
    if not 0 <= seq <= MAX_SEQ:
        raise ValueError("SEQ_RANGE")
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def open_frame(key: Secret, last_seq: int, aad: FrameAad, aad_bytes: bytes, ct: bytes) -> Secret:
    """Decrypts one c2t frame whose seq is above `last_seq` (-1: nothing accepted yet)."""
    if aad.seq <= last_seq:
        raise SessionReject(SessionRejectCode.SEQ_REJECTED)
    try:
        plaintext = AESGCM(key.reveal()).decrypt(_nonce(aad.seq), ct, aad_bytes)
    except InvalidTag:
        raise SessionReject(SessionRejectCode.AUTH_FAILED) from None
    return Secret(plaintext)


class T2cSealer:
    """Sole owner of sk_t2c and the t2c counter (D2-16, R-5); created by ChannelServer on Open."""

    def __init__(self, sk_t2c: Secret) -> None:
        self._key = sk_t2c
        self._next_seq = 0

    def seal_open_result(self, aad: OpenResultAad, plaintext: bytes) -> tuple[bytes, bytes]:
        if self._next_seq != 0:
            raise SessionReject(SessionRejectCode.USED)
        self._next_seq = 1
        aad_bytes = encode_open_result_aad(aad)
        return aad_bytes, self._encrypt(0, plaintext, aad_bytes)

    def seal_frame_result(
        self, op: str, session_id: bytes, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        seq = self._next_seq
        if seq == 0:
            raise SessionReject(SessionRejectCode.USED)
        if seq > MAX_SEQ:
            raise SessionReject(SessionRejectCode.EXHAUSTED)
        self._next_seq = seq + 1
        aad_bytes = encode_frame_aad(FrameAad(session_id=session_id, seq=seq, op=op))
        return aad_bytes, self._encrypt(seq, plaintext, aad_bytes)

    def _encrypt(self, seq: int, plaintext: bytes, aad_bytes: bytes) -> bytes:
        """The only AES-GCM encryption under sk_t2c; the caller allocated and persisted `seq`."""
        return AESGCM(self._key.reveal()).encrypt(_nonce(seq), plaintext, aad_bytes)

    def wipe(self) -> None:
        raise NotImplementedError("T-23")


class Session:
    """Constructed only by SessionTable."""

    session_id: bytes
    client_id: str
    opened_at: float
    last_activity: float

    _sk_c2t: Secret
    _t2c: T2cSealer
    _last_c2t_seq: int

    @classmethod
    def _start(
        cls, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer, now: float
    ) -> "Session":
        session = cls.__new__(cls)
        session.session_id = session_id
        session.client_id = client_id
        session.opened_at = now
        session.last_activity = now
        session._sk_c2t = sk_c2t
        session._t2c = t2c
        session._last_c2t_seq = -1
        return session

    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret:
        if aad.session_id != self.session_id:
            raise SessionReject(SessionRejectCode.AUTH_FAILED)
        plaintext = open_frame(self._sk_c2t, self._last_c2t_seq, aad, aad_bytes, ct)
        self._last_c2t_seq = aad.seq
        self.last_activity = now
        return plaintext

    def seal_open_result(self, request_id: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        raise NotImplementedError("T-23")

    def seal_t2c(self, op: str, plaintext: bytes) -> tuple[FrameAad, bytes, bytes]:
        raise NotImplementedError("T-23")


class SessionTable:
    def __init__(
        self,
        *,
        instance_id: str,
        max_sessions: int,
        idle_timeout_s: int,
        evict_min_idle_s: int,
        on_close: Callable[[SessionInfo, CloseReason], None],
        clock: Callable[[], float],
    ) -> None:
        self._clock = clock
        self._sessions: dict[bytes, Session] = {}

    def create(
        self, *, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer
    ) -> Session:
        session = Session._start(session_id, client_id, sk_c2t, t2c, self._clock())
        self._sessions[session_id] = session
        return session

    def get(self, session_id: bytes) -> Session | None:
        raise NotImplementedError("T-23")

    def close(self, session_id: bytes, reason: CloseReason) -> None:
        raise NotImplementedError("T-23")

    def expire_idle(self) -> int:
        raise NotImplementedError("T-23")

    def close_all(self) -> None:
        raise NotImplementedError("T-23")
