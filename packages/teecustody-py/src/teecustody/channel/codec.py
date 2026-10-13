"""Channel codec: the single place channel structures are encoded and decoded (INC-2-API §4.5).

This module holds no keys and performs no AEAD. Constants, errors and dataclasses are frozen;
function bodies belong to T-07.
"""

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal

from teecustody import wire
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


_U32_MAX: Final = 2**32 - 1
_KEY_LEN: Final = 32  # enc, pub, IK_pub
_ID_LEN: Final = 16  # request_id, session_id
_CT_MIN: Final = 16
_OPEN_CT_MAX: Final = 2048
_FRAME_CT_MAX: Final = 32784  # frame request and both results
_OPEN_REQUEST_KEYS: Final = frozenset({"kind", "aad", "enc", "ct"})
_FRAME_REQUEST_KEYS: Final = frozenset({"kind", "aad", "ct"})
_OPEN_AAD_KEYS: Final = frozenset(
    {"proto", "client_id", "instance_id", "prekey_id", "request_id", "timestamp"}
)
_FRAME_AAD_KEYS: Final = frozenset({"session_id", "seq", "op"})


# Checks shared by every encoder and decoder. Each raises ValueError("<FIELD>_RANGE"); `bool` is
# never an `int` and patterns are applied with `fullmatch` only (R-7).
def _uint(value: object, maximum: int, field: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{field}_RANGE")
    return value


def _bytes(value: object, field: str) -> bytes:
    if type(value) is not bytes:
        raise ValueError(f"{field}_RANGE")
    return value


def _sized_bytes(value: object, minimum: int, maximum: int, field: str) -> bytes:
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field}_RANGE")
    return value


def _text(value: object, pattern: re.Pattern[str], field: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ValueError(f"{field}_RANGE")
    return value


def _fields(value: CanonicalValue, keys: frozenset[str]) -> dict[str, CanonicalValue]:
    """A decoded map with exactly `keys` (no unknown, no missing key)."""
    if type(value) is not dict or value.keys() != keys:
        raise ValueError("SCHEMA_RANGE")
    return value


def _kind(value: CanonicalValue) -> CanonicalValue:
    return value.get("kind") if type(value) is dict else None


def encode_bundle(b: PreKeyBundle) -> bytes:
    raise NotImplementedError("T-07")


def decode_bundle(data: bytes, limits: DecodeLimits) -> PreKeyBundle:
    raise NotImplementedError("T-07")


def decode_request(
    body: bytes, limits: BoundaryLimits
) -> OpenRequestEnvelope | FrameRequestEnvelope:
    if len(body) > limits.max_request_bytes:
        raise EnvelopeError(EnvelopeErrorCode.TOO_LARGE)
    try:
        return _parse_request(body, limits)
    except (wire.WireError, ValueError):
        pass
    raise EnvelopeError(EnvelopeErrorCode.INVALID)


def _parse_request(
    body: bytes, limits: BoundaryLimits
) -> OpenRequestEnvelope | FrameRequestEnvelope:
    envelope = wire.decode(body, limits.envelope_decode)
    kind = _kind(envelope)
    if kind == "open":
        fields = _fields(envelope, _OPEN_REQUEST_KEYS)
        aad_bytes = _bytes(fields["aad"], "AAD")
        return OpenRequestEnvelope(
            aad_bytes=aad_bytes,
            aad=_open_aad(wire.decode(aad_bytes, limits.aad_decode)),
            enc=_sized_bytes(fields["enc"], _KEY_LEN, _KEY_LEN, "ENC"),
            ct=_sized_bytes(fields["ct"], _CT_MIN, _OPEN_CT_MAX, "CT"),
        )
    if kind == "frame":
        fields = _fields(envelope, _FRAME_REQUEST_KEYS)
        aad_bytes = _bytes(fields["aad"], "AAD")
        return FrameRequestEnvelope(
            aad_bytes=aad_bytes,
            aad=_frame_aad(wire.decode(aad_bytes, limits.aad_decode)),
            ct=_sized_bytes(fields["ct"], _CT_MIN, _FRAME_CT_MAX, "CT"),
        )
    raise ValueError("KIND_RANGE")


def _open_aad(value: CanonicalValue) -> OpenAad:
    fields = _fields(value, _OPEN_AAD_KEYS)
    if fields["proto"] != wire.PROTO:
        raise ValueError("PROTO_RANGE")
    return OpenAad(
        client_id=_text(fields["client_id"], CLIENT_ID_PATTERN, "CLIENT_ID"),
        instance_id=_text(fields["instance_id"], INSTANCE_ID_PATTERN, "INSTANCE_ID"),
        prekey_id=_uint(fields["prekey_id"], _U32_MAX, "PREKEY_ID"),
        request_id=_sized_bytes(fields["request_id"], _ID_LEN, _ID_LEN, "REQUEST_ID"),
        timestamp=_uint(fields["timestamp"], MAX_UNIX_S, "TIMESTAMP"),
    )


def _frame_aad(value: CanonicalValue) -> FrameAad:
    fields = _fields(value, _FRAME_AAD_KEYS)
    return FrameAad(
        session_id=_sized_bytes(fields["session_id"], _ID_LEN, _ID_LEN, "SESSION_ID"),
        seq=_uint(fields["seq"], MAX_SEQ, "SEQ"),
        op=_text(fields["op"], OP_NAME_PATTERN, "OP"),
    )


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
