"""Session keys, the t2c sealer and the session table (INC-2-API §4.9; API-TL §2; D2-16, R-5, R-8).

`SessionRejectCode` and `SessionReject` are frozen (T-04). Nothing here logs: the `on_close`
owner does (TL-2).
"""

import contextlib
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
    if aad.seq <= last_seq or not 0 <= aad.seq <= MAX_SEQ:
        raise SessionReject(SessionRejectCode.SEQ_REJECTED)
    try:
        plaintext = AESGCM(key.reveal()).decrypt(_nonce(aad.seq), ct, aad_bytes)
    except InvalidTag:
        raise SessionReject(SessionRejectCode.AUTH_FAILED) from None
    if not plaintext:  # a frame always carries CBOR; a Secret cannot be empty
        raise SessionReject(SessionRejectCode.AUTH_FAILED)
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
        return aad_bytes, AESGCM(self._key.reveal()).encrypt(_nonce(0), plaintext, aad_bytes)

    def seal_frame_result(
        self, op: str, session_id: bytes, plaintext: bytes
    ) -> tuple[bytes, bytes]:
        _aad, aad_bytes, ct = self._seal_frame(op, session_id, plaintext)
        return aad_bytes, ct

    def wipe(self) -> None:
        self._key.wipe()

    def _seal_frame(
        self, op: str, session_id: bytes, plaintext: bytes
    ) -> tuple[FrameAad, bytes, bytes]:
        """Allocates the next t2c seq and persists it before the one AES-GCM call (R-5)."""
        seq = self._next_seq
        if seq == 0:
            raise SessionReject(SessionRejectCode.USED)
        if seq > MAX_SEQ:
            raise SessionReject(SessionRejectCode.EXHAUSTED)
        self._next_seq = seq + 1
        aad = FrameAad(session_id=session_id, seq=seq, op=op)
        aad_bytes = encode_frame_aad(aad)
        ct = AESGCM(self._key.reveal()).encrypt(_nonce(seq), plaintext, aad_bytes)
        return aad, aad_bytes, ct

    def _is_fresh(self) -> bool:
        return self._next_seq == 0


class Session:
    """Constructed only by SessionTable."""

    session_id: bytes
    client_id: str
    opened_at: float
    last_activity: float

    _sk_c2t: Secret
    _t2c: T2cSealer
    _last_c2t_seq: int

    def __init__(self) -> None:
        raise TypeError("SESSION_CONSTRUCTOR")

    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret:
        if aad.session_id != self.session_id:
            raise SessionReject(SessionRejectCode.AUTH_FAILED)
        plaintext = open_frame(self._sk_c2t, self._last_c2t_seq, aad, aad_bytes, ct)
        self._last_c2t_seq = aad.seq
        self.last_activity = now
        return plaintext

    def seal_open_result(self, request_id: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        aad = OpenResultAad(session_id=self.session_id, request_id=request_id)
        return self._t2c.seal_open_result(aad, plaintext)

    def seal_t2c(self, op: str, plaintext: bytes) -> tuple[FrameAad, bytes, bytes]:
        return self._t2c._seal_frame(op, self.session_id, plaintext)

    def _wipe(self) -> None:
        self._sk_c2t.wipe()
        self._t2c.wipe()


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
        if min(max_sessions, idle_timeout_s, evict_min_idle_s) < 1:
            raise ValueError("SESSION_LIMITS")
        if evict_min_idle_s > idle_timeout_s:
            raise ValueError("SESSION_LIMITS")
        self._instance_id = instance_id
        self._max_sessions = max_sessions
        self._idle_timeout_s = idle_timeout_s
        self._evict_min_idle_s = evict_min_idle_s
        self._on_close = on_close
        self._clock = clock
        self._sessions: dict[bytes, Session] = {}

    def create(
        self, *, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer
    ) -> Session:
        # A1: checked first; nothing is owned, closed, expired or evicted when it is refused.
        if session_id in self._sessions:
            raise ValueError("SESSION_ID_IN_USE")
        if not t2c._is_fresh():
            raise ValueError("T2C_USED")
        for existing in list(self._sessions.values()):
            if existing.client_id == client_id:
                self.close(existing.session_id, CloseReason.REPLACED)
        if len(self._sessions) >= self._max_sessions:
            self.expire_idle()
        if len(self._sessions) >= self._max_sessions:
            self._evict_one()
        now = self._clock()
        # Built here so that no Session method ever takes a key (R-5, INC-2-API §4.9).
        session = Session.__new__(Session)
        session.session_id = session_id
        session.client_id = client_id
        session.opened_at = now
        session.last_activity = now
        session._sk_c2t = sk_c2t
        session._t2c = t2c
        session._last_c2t_seq = -1
        self._sessions[session_id] = session
        return session

    def get(self, session_id: bytes) -> Session | None:
        return self._sessions.get(session_id)

    def close(self, session_id: bytes, reason: CloseReason) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        session._wipe()
        info = SessionInfo(
            client_id=session.client_id,
            session_id=session.session_id,
            instance_id=self._instance_id,
        )
        # The owner's hook logs and reports (TL-2); its failure never stops a close.
        with contextlib.suppress(Exception):
            self._on_close(info, reason)

    def expire_idle(self) -> int:
        now = self._clock()
        idle = [
            session.session_id
            for session in self._sessions.values()
            if now - session.last_activity >= self._idle_timeout_s
        ]
        for session_id in idle:
            self.close(session_id, CloseReason.IDLE_TIMEOUT)
        return len(idle)

    def close_all(self) -> None:
        for session_id in list(self._sessions):
            self.close(session_id, CloseReason.SHUTDOWN)

    def _evict_one(self) -> None:
        """R-8: evict the least recently active session (ties: smallest id) if idle long enough."""
        victim = min(
            self._sessions.values(),
            key=lambda session: (session.last_activity, session.session_id),
        )
        if self._clock() - victim.last_activity < self._evict_min_idle_s:
            raise OverflowError("SESSIONS_FULL")
        self.close(victim.session_id, CloseReason.EVICTED)
