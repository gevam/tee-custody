"""Channel codec: the single place channel structures are encoded and decoded (INC-2-API §4.5).

This module holds no keys and performs no AEAD. Constants, errors and dataclasses are frozen;
function bodies belong to T-07.
"""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal

from teecustody.channel.ports import (
    EnrollPayload,
    HandlerError,
    HandlerOk,
    OpenAccepted,
    OpenRejected,
    OpenSessionPayload,
)
from teecustody.config import BoundaryLimits
from teecustody.secrets import Secret
from teecustody.wire.types import CanonicalValue, DecodeLimits


class EnvelopeErrorCode(StrEnum):
    TOO_LARGE = "TOO_LARGE"
    INVALID = "INVALID"


class EnvelopeError(Exception):
    """Carries only a stable code; `str(err)` is the code value and nothing else."""

    code: EnvelopeErrorCode

    def __init__(self, code: EnvelopeErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


HEX32_PATTERN: Final = re.compile(r"[0-9a-f]{32}")  # instance_id, client_id; fullmatch only
CLIENT_ID_PATTERN: Final = HEX32_PATTERN
INSTANCE_ID_PATTERN: Final = HEX32_PATTERN
OP_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
ERROR_CODE_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
MAX_UNIX_S: Final = 2**53 - 1
MAX_SEQ: Final = 2**53 - 1


@dataclass(frozen=True, slots=True)
class PreKeyEntry:
    id: int
    pub: bytes
    not_after: int
    sig: bytes


@dataclass(frozen=True, slots=True)
class PreKeyBundle:
    instance_id: str
    token: str = field(repr=False)
    ik_pub: bytes
    published_at: int
    prekeys: tuple[PreKeyEntry, ...]


@dataclass(frozen=True, slots=True)
class OpenAad:
    client_id: str
    instance_id: str
    prekey_id: int
    request_id: bytes
    timestamp: int


@dataclass(frozen=True, slots=True)
class FrameAad:
    session_id: bytes
    seq: int
    op: str


@dataclass(frozen=True, slots=True)
class OpenResultAad:
    session_id: bytes | None
    request_id: bytes  # seq is always 0


@dataclass(frozen=True, slots=True)
class OpenRequestEnvelope:
    aad_bytes: bytes
    aad: OpenAad
    enc: bytes
    ct: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class FrameRequestEnvelope:
    aad_bytes: bytes
    aad: FrameAad
    ct: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class OpenResultEnvelope:
    aad_bytes: bytes
    aad: OpenResultAad
    ct: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class FrameResultEnvelope:
    aad_bytes: bytes
    aad: FrameAad
    ct: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class OpenResultBody:
    ok: bool
    payload: CanonicalValue = field(default=None, repr=False)
    error: str | None = None


def encode_bundle(b: PreKeyBundle) -> bytes:
    raise NotImplementedError("T-07")


def decode_bundle(data: bytes, limits: DecodeLimits) -> PreKeyBundle:
    raise NotImplementedError("T-07")


def decode_request(
    body: bytes, limits: BoundaryLimits
) -> OpenRequestEnvelope | FrameRequestEnvelope:
    raise NotImplementedError("T-07")


def decode_open_payload(pt: Secret, limits: DecodeLimits) -> OpenSessionPayload | EnrollPayload:
    raise NotImplementedError("T-07")


def encode_open_result_aad(aad: OpenResultAad) -> bytes:
    raise NotImplementedError("T-07")


def encode_frame_aad(aad: FrameAad) -> bytes:
    raise NotImplementedError("T-07")


def encode_open_result_plaintext(result: OpenAccepted | OpenRejected) -> bytes:
    raise NotImplementedError("T-07")


def encode_frame_result_plaintext(re: int, body: HandlerOk | HandlerError) -> bytes:
    raise NotImplementedError("T-07")


def encode_response_envelope(
    kind: Literal["open_result", "frame_result"], aad_bytes: bytes, ct: bytes
) -> bytes:
    raise NotImplementedError("T-07")


def decode_response(
    body: bytes, limits: BoundaryLimits
) -> OpenResultEnvelope | FrameResultEnvelope:
    raise NotImplementedError("T-07")


def decode_open_result_plaintext(
    pt: bytes, aad: OpenResultAad, limits: DecodeLimits
) -> OpenResultBody:
    raise NotImplementedError("T-07")


def prekey_signing_message(
    instance_id: str, prekey_id: int, pub: bytes, not_after: int, image_digest: str
) -> bytes:
    raise NotImplementedError("T-07")


def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes:
    raise NotImplementedError("T-07")


__all__ = [
    "CLIENT_ID_PATTERN",
    "ERROR_CODE_PATTERN",
    "HEX32_PATTERN",
    "INSTANCE_ID_PATTERN",
    "MAX_SEQ",
    "MAX_UNIX_S",
    "OP_NAME_PATTERN",
    "EnrollPayload",
    "EnvelopeError",
    "EnvelopeErrorCode",
    "FrameAad",
    "FrameRequestEnvelope",
    "FrameResultEnvelope",
    "OpenAad",
    "OpenRequestEnvelope",
    "OpenResultAad",
    "OpenResultBody",
    "OpenResultEnvelope",
    "OpenSessionPayload",
    "PreKeyBundle",
    "PreKeyEntry",
    "decode_bundle",
    "decode_open_payload",
    "decode_open_result_plaintext",
    "decode_request",
    "decode_response",
    "encode_bundle",
    "encode_frame_aad",
    "encode_frame_result_plaintext",
    "encode_open_result_aad",
    "encode_open_result_plaintext",
    "encode_response_envelope",
    "hpke_info",
    "prekey_signing_message",
]
