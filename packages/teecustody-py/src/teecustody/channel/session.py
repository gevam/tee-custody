"""Session keys, the t2c sealer and the session table (INC-2-API §4.9; API-TL §2; D2-16, R-5, R-8).

`SessionRejectCode` and `SessionReject` are frozen; bodies belong to T-23.
"""

from collections.abc import Callable
from enum import StrEnum

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
    return b"\x00" * 4 + seq.to_bytes(8, "big")


def open_frame(key: Secret, last_seq: int, aad: FrameAad, aad_bytes: bytes, ct: bytes) -> Secret:
    raise NotImplementedError("T-23")


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

    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret:
        raise NotImplementedError("T-23")

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
        raise NotImplementedError("T-23")

    def create(
        self, *, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer
    ) -> Session:
        raise NotImplementedError("T-23")

    def get(self, session_id: bytes) -> Session | None:
        raise NotImplementedError("T-23")

    def close(self, session_id: bytes, reason: CloseReason) -> None:
        raise NotImplementedError("T-23")

    def expire_idle(self) -> int:
        raise NotImplementedError("T-23")

    def close_all(self) -> None:
        raise NotImplementedError("T-23")
