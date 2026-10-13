"""Channel codec: the single place channel structures are encoded and decoded (INC-2-API §4.5).

This module holds no keys and performs no AEAD. Constants, errors and dataclasses are frozen;
function bodies belong to T-07.
"""

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import pairwise
from typing import Final, Literal

from teecustody import wire
from teecustody.attest.claims import IMAGE_DIGEST_PATTERN
from teecustody.channel.ports import (
    EnrollPayload,
    HandlerError,
    HandlerOk,
    OpenAccepted,
    OpenRejected,
    OpenSessionPayload,
    RemoteErrorCode,
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
_PREKEY_DOMAIN: Final = b"prekey-v1"
_KEY_LEN: Final = 32  # enc, pub, IK_pub, cs
_ID_LEN: Final = 16  # request_id, session_id, key_id
_CT_MIN: Final = 16
_OPEN_CT_MAX: Final = 2048
_FRAME_CT_MAX: Final = 32784  # frame request and both results
_OPEN_REQUEST_KEYS: Final = frozenset({"kind", "aad", "enc", "ct"})
_FRAME_REQUEST_KEYS: Final = frozenset({"kind", "aad", "ct"})
_OPEN_AAD_KEYS: Final = frozenset(
    {"proto", "client_id", "instance_id", "prekey_id", "request_id", "timestamp"}
)
_FRAME_AAD_KEYS: Final = frozenset({"session_id", "seq", "op"})
_BUNDLE_KEYS: Final = frozenset({"instance_id", "token", "IK_pub", "published_at", "prekeys"})
_PREKEY_KEYS: Final = frozenset({"id", "pub", "not_after", "sig"})
_OPEN_RESULT_AAD_KEYS: Final = frozenset({"session_id", "request_id", "seq"})
_RESPONSE_KEYS: Final = frozenset({"kind", "aad", "ct"})
_RESPONSE_KINDS: Final = ("open_result", "frame_result")
# Encoders re-check the aad they wrap with the default aad bounds (the decoders take theirs from
# BoundaryLimits).
_ENCODER_AAD_LIMITS: Final = BoundaryLimits().aad_decode
_OPEN_SESSION_KEYS: Final = frozenset({"op", "cs", "key_id", "epoch"})
_ENROLL_KEYS: Final = frozenset({"op"})
_RESULT_OK_KEYS: Final = frozenset({"ok", "payload"})
_RESULT_ERROR_KEYS: Final = frozenset({"ok", "error"})
_SIG_LEN: Final = 64
_MAX_PREKEYS: Final = 256
_MAX_TOKEN_BYTES: Final = 16384


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


def _member(value: CanonicalValue, key: str) -> CanonicalValue:
    """`value[key]` if `value` is a map holding `key`, else `None` (dispatch before `_fields`)."""
    return value.get(key) if type(value) is dict else None


def encode_bundle(b: PreKeyBundle) -> bytes:
    checked = _bundle(
        b.instance_id,
        b.token,
        b.ik_pub,
        b.published_at,
        [_prekey(p.id, p.pub, p.not_after, p.sig) for p in b.prekeys],
    )
    return wire.encode(
        {
            "instance_id": checked.instance_id,
            "token": checked.token,
            "IK_pub": checked.ik_pub,
            "published_at": checked.published_at,
            "prekeys": [
                {"id": p.id, "pub": p.pub, "not_after": p.not_after, "sig": p.sig}
                for p in checked.prekeys
            ],
        }
    )


def decode_bundle(data: bytes, limits: DecodeLimits) -> PreKeyBundle:
    try:
        return _parse_bundle(wire.decode(data, limits))
    except (wire.WireError, ValueError):
        pass
    raise EnvelopeError(EnvelopeErrorCode.INVALID)


def _parse_bundle(value: CanonicalValue) -> PreKeyBundle:
    fields = _fields(value, _BUNDLE_KEYS)
    prekeys = fields["prekeys"]
    if type(prekeys) is not list:
        raise ValueError("PREKEYS_RANGE")
    entries = []
    for item in prekeys:
        entry = _fields(item, _PREKEY_KEYS)
        entries.append(_prekey(entry["id"], entry["pub"], entry["not_after"], entry["sig"]))
    return _bundle(
        fields["instance_id"], fields["token"], fields["IK_pub"], fields["published_at"], entries
    )


def _prekey(prekey_id: object, pub: object, not_after: object, sig: object) -> PreKeyEntry:
    return PreKeyEntry(
        id=_uint(prekey_id, _U32_MAX, "PREKEY_ID"),
        pub=_sized_bytes(pub, _KEY_LEN, _KEY_LEN, "PUB"),
        not_after=_uint(not_after, MAX_UNIX_S, "NOT_AFTER"),
        sig=_sized_bytes(sig, _SIG_LEN, _SIG_LEN, "SIG"),
    )


def _bundle(
    instance_id: object,
    token: object,
    ik_pub: object,
    published_at: object,
    prekeys: list[PreKeyEntry],
) -> PreKeyBundle:
    if not 1 <= len(prekeys) <= _MAX_PREKEYS:
        raise ValueError("PREKEYS_RANGE")
    for previous, current in pairwise(prekeys):
        if current.id <= previous.id:
            raise ValueError("PREKEY_ID_RANGE")  # strictly ascending, hence unique (R-2)
    if type(token) is not str or not 1 <= len(token.encode()) <= _MAX_TOKEN_BYTES:
        raise ValueError("TOKEN_RANGE")
    return PreKeyBundle(
        instance_id=_text(instance_id, INSTANCE_ID_PATTERN, "INSTANCE_ID"),
        token=token,
        ik_pub=_sized_bytes(ik_pub, _KEY_LEN, _KEY_LEN, "IK_PUB"),
        published_at=_uint(published_at, MAX_UNIX_S, "PUBLISHED_AT"),
        prekeys=tuple(prekeys),
    )


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
    kind = _member(envelope, "kind")
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
    return _checked_frame_aad(fields["session_id"], fields["seq"], fields["op"])


def _checked_frame_aad(session_id: object, seq: object, op: object) -> FrameAad:
    return FrameAad(
        session_id=_sized_bytes(session_id, _ID_LEN, _ID_LEN, "SESSION_ID"),
        seq=_uint(seq, MAX_SEQ, "SEQ"),
        op=_text(op, OP_NAME_PATTERN, "OP"),
    )


def decode_open_payload(pt: Secret, limits: DecodeLimits) -> OpenSessionPayload | EnrollPayload:
    try:
        return _parse_open_payload(wire.decode(pt.reveal(), limits))
    except (wire.WireError, ValueError):
        pass
    raise EnvelopeError(EnvelopeErrorCode.INVALID)


def _parse_open_payload(value: CanonicalValue) -> OpenSessionPayload | EnrollPayload:
    if _member(value, "op") == "enroll":
        _fields(value, _ENROLL_KEYS)
        return EnrollPayload()
    fields = _fields(value, _OPEN_SESSION_KEYS)
    if fields["op"] != "open_session":
        raise ValueError("OP_RANGE")
    key_id = _sized_bytes(fields["key_id"], _ID_LEN, _ID_LEN, "KEY_ID")
    epoch = _uint(fields["epoch"], _U32_MAX, "EPOCH")
    # Last, so no Secret exists unless the whole payload is valid; cs lives only in it (NFR-3).
    cs = Secret(_sized_bytes(fields["cs"], _KEY_LEN, _KEY_LEN, "CS"))
    return OpenSessionPayload(cs=cs, key_id=key_id, epoch=epoch)


def encode_open_result_aad(aad: OpenResultAad) -> bytes:
    checked = _checked_open_result_aad(aad.session_id, aad.request_id)
    return wire.encode(
        {"session_id": checked.session_id, "request_id": checked.request_id, "seq": 0}
    )


def encode_frame_aad(aad: FrameAad) -> bytes:
    checked = _checked_frame_aad(aad.session_id, aad.seq, aad.op)
    return wire.encode({"session_id": checked.session_id, "seq": checked.seq, "op": checked.op})


def encode_open_result_plaintext(result: OpenAccepted | OpenRejected) -> bytes:
    if isinstance(result, OpenAccepted):
        return wire.encode({"ok": True, "payload": result.payload})
    return wire.encode({"ok": False, "error": _error_code(result.error)})


def encode_frame_result_plaintext(re: int, body: HandlerOk | HandlerError) -> bytes:
    checked_re = _uint(re, MAX_SEQ, "RE")
    if isinstance(body, HandlerOk):
        return wire.encode({"re": checked_re, "ok": True, "payload": body.payload})
    return wire.encode({"re": checked_re, "ok": False, "error": _error_code(body.error)})


def encode_response_envelope(
    kind: Literal["open_result", "frame_result"], aad_bytes: bytes, ct: bytes
) -> bytes:
    if type(kind) is not str or kind not in _RESPONSE_KINDS:
        raise ValueError("KIND_RANGE")
    if not _is_result_aad(kind, aad_bytes):
        raise ValueError("AAD_RANGE")
    checked_ct = _sized_bytes(ct, _CT_MIN, _FRAME_CT_MAX, "CT")
    return wire.encode({"kind": kind, "aad": aad_bytes, "ct": checked_ct})


def _is_result_aad(kind: str, aad_bytes: object) -> bool:
    try:
        _result_aad(kind, wire.decode(_bytes(aad_bytes, "AAD"), _ENCODER_AAD_LIMITS))
    except (wire.WireError, ValueError):
        return False
    return True


def decode_response(
    body: bytes, limits: BoundaryLimits
) -> OpenResultEnvelope | FrameResultEnvelope:
    if len(body) > limits.max_request_bytes:
        raise EnvelopeError(EnvelopeErrorCode.TOO_LARGE)
    try:
        return _parse_response(body, limits)
    except (wire.WireError, ValueError):
        pass
    raise EnvelopeError(EnvelopeErrorCode.INVALID)


def _parse_response(
    body: bytes, limits: BoundaryLimits
) -> OpenResultEnvelope | FrameResultEnvelope:
    envelope = wire.decode(body, limits.envelope_decode)
    kind = _member(envelope, "kind")
    if kind not in _RESPONSE_KINDS:
        raise ValueError("KIND_RANGE")
    fields = _fields(envelope, _RESPONSE_KEYS)
    aad_bytes = _bytes(fields["aad"], "AAD")
    aad = _result_aad(kind, wire.decode(aad_bytes, limits.aad_decode))
    ct = _sized_bytes(fields["ct"], _CT_MIN, _FRAME_CT_MAX, "CT")
    if isinstance(aad, OpenResultAad):
        return OpenResultEnvelope(aad_bytes=aad_bytes, aad=aad, ct=ct)
    return FrameResultEnvelope(aad_bytes=aad_bytes, aad=aad, ct=ct)


def _result_aad(kind: CanonicalValue, value: CanonicalValue) -> OpenResultAad | FrameAad:
    if kind == "open_result":
        return _open_result_aad(value)
    return _frame_aad(value)


def _open_result_aad(value: CanonicalValue) -> OpenResultAad:
    fields = _fields(value, _OPEN_RESULT_AAD_KEYS)
    _uint(fields["seq"], 0, "SEQ")  # the literal 0: t2c nonce 0 belongs to the open_result
    return _checked_open_result_aad(fields["session_id"], fields["request_id"])


def _checked_open_result_aad(session_id: object, request_id: object) -> OpenResultAad:
    return OpenResultAad(
        session_id=None
        if session_id is None
        else _sized_bytes(session_id, _ID_LEN, _ID_LEN, "SESSION_ID"),
        request_id=_sized_bytes(request_id, _ID_LEN, _ID_LEN, "REQUEST_ID"),
    )


def _error_code(error: object) -> str:
    code = error.value if isinstance(error, RemoteErrorCode) else error
    return _text(code, ERROR_CODE_PATTERN, "ERROR")


def decode_open_result_plaintext(
    pt: bytes, aad: OpenResultAad, limits: DecodeLimits
) -> OpenResultBody:
    try:
        body = _parse_open_result(wire.decode(pt, limits))
        if body.ok is (aad.session_id is not None):  # R-3
            return body
    except (wire.WireError, ValueError):
        pass
    raise EnvelopeError(EnvelopeErrorCode.INVALID)


def _parse_open_result(value: CanonicalValue) -> OpenResultBody:
    if _member(value, "ok") is True:
        return OpenResultBody(ok=True, payload=_fields(value, _RESULT_OK_KEYS)["payload"])
    fields = _fields(value, _RESULT_ERROR_KEYS)
    if fields["ok"] is not False:
        raise ValueError("OK_RANGE")
    return OpenResultBody(ok=False, error=_text(fields["error"], ERROR_CODE_PATTERN, "ERROR"))


def prekey_signing_message(
    instance_id: str, prekey_id: int, pub: bytes, not_after: int, image_digest: str
) -> bytes:
    preimage = b"".join(
        (
            _PREKEY_DOMAIN,
            _text(instance_id, INSTANCE_ID_PATTERN, "INSTANCE_ID").encode("ascii"),
            _uint(prekey_id, _U32_MAX, "PREKEY_ID").to_bytes(4, "big"),
            _sized_bytes(pub, _KEY_LEN, _KEY_LEN, "PUB"),
            _uint(not_after, MAX_UNIX_S, "NOT_AFTER").to_bytes(8, "big"),
            _text(image_digest, IMAGE_DIGEST_PATTERN, "IMAGE_DIGEST").encode("ascii"),
        )
    )
    return hashlib.sha256(preimage).digest()


def hpke_info(ik_pub: bytes, prekey_id: int) -> bytes:
    checked_ik_pub = _sized_bytes(ik_pub, _KEY_LEN, _KEY_LEN, "IK_PUB")
    suffix = _uint(prekey_id, _U32_MAX, "PREKEY_ID").to_bytes(4, "big")
    return wire.PROTO.encode("ascii") + hashlib.sha256(checked_ik_pub).digest() + suffix


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
